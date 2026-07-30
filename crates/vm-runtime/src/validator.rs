//! Deploy-time profile validation.
//!
//! A component binary is validated once, before it enters state; a
//! non-conforming artifact never deploys. Two passes: wasmparser's validator
//! under the profile's feature set (rejecting floats, SIMD, threads,
//! exceptions, tail calls, memory64, GC, and Component Model async), then a
//! structural pass enforcing the [`crate::profile`] limits and the
//! component-level import allowlist.

use thiserror::Error;
use wasmparser::{
    ComponentTypeRef, CompositeInnerType, FunctionBody, Operator, Parser, Payload, TypeRef,
    Validator, WasmFeatures,
};

use crate::profile;

/// A profile violation. Every variant is a deterministic deploy-time verdict.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// The artifact exceeds [`profile::MAX_COMPONENT_BYTES`].
    #[error("component of {actual} bytes exceeds the {max}-byte limit")]
    ComponentTooLarge {
        /// Artifact size.
        actual: usize,
        /// The limit it exceeds.
        max: usize,
    },
    /// The binary is not a component (a bare core module, or garbage).
    #[error("artifact is not a component")]
    NotAComponent,
    /// Rejected by validation under the profile feature set.
    #[error("outside the profile feature set: {0}")]
    Feature(String),
    /// A component-level import outside the kernel world.
    #[error("import outside the kernel world: {0}")]
    ForbiddenImport(String),
    /// A nested component; contract artifacts are one component deep.
    #[error("nested components are not permitted")]
    NestedComponent,
    /// A core module start section; instantiation must be inert.
    #[error("start sections are not permitted")]
    StartSection,
    /// A structural limit exceeded; the message names the limit.
    #[error("structural limit exceeded: {0}")]
    Structural(String),
}

/// The profile's wasm feature set: wasmparser defaults minus every proposal
/// the profile disables.
fn profile_features() -> WasmFeatures {
    let mut features = WasmFeatures::default();
    features.remove(WasmFeatures::FLOATS);
    features.remove(WasmFeatures::SIMD);
    features.remove(WasmFeatures::RELAXED_SIMD);
    features.remove(WasmFeatures::THREADS);
    features.remove(WasmFeatures::SHARED_EVERYTHING_THREADS);
    features.remove(WasmFeatures::EXCEPTIONS);
    features.remove(WasmFeatures::LEGACY_EXCEPTIONS);
    features.remove(WasmFeatures::TAIL_CALL);
    features.remove(WasmFeatures::MEMORY64);
    features.remove(WasmFeatures::GC);
    features.remove(WasmFeatures::CM_ASYNC);
    features
}

/// Validates a component artifact against the deterministic profile.
///
/// # Errors
///
/// Returns the first [`ProfileError`] encountered; verdicts are deterministic
/// functions of the bytes.
pub fn validate_component(bytes: &[u8]) -> Result<(), ProfileError> {
    if bytes.len() > profile::MAX_COMPONENT_BYTES {
        return Err(ProfileError::ComponentTooLarge {
            actual: bytes.len(),
            max: profile::MAX_COMPONENT_BYTES,
        });
    }
    if !Parser::is_component(bytes) {
        return Err(ProfileError::NotAComponent);
    }

    Validator::new_with_features(profile_features())
        .validate_all(bytes)
        .map_err(|e| ProfileError::Feature(e.to_string()))?;

    structural_pass(bytes)
}

fn structural_pass(bytes: &[u8]) -> Result<(), ProfileError> {
    let mut core_modules = 0usize;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| ProfileError::Feature(e.to_string()))?;
        match payload {
            Payload::ModuleSection {
                unchecked_range, ..
            } => {
                core_modules += 1;
                if core_modules > profile::MAX_CORE_MODULES {
                    return Err(ProfileError::Structural(format!(
                        "more than {} core modules",
                        profile::MAX_CORE_MODULES
                    )));
                }
                validate_core_module(&bytes[unchecked_range])?;
            }
            Payload::ComponentSection { .. } => return Err(ProfileError::NestedComponent),
            Payload::ComponentImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    let name = import.name.0;
                    // Type imports confer no capability — they are how a
                    // world-level `use` of a kernel resource type encodes —
                    // so only value-carrying imports are gated.
                    if matches!(import.ty, ComponentTypeRef::Type(_)) {
                        continue;
                    }
                    if !name.starts_with(profile::KERNEL_IMPORT_PREFIX) {
                        return Err(ProfileError::ForbiddenImport(name.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_core_module(bytes: &[u8]) -> Result<(), ProfileError> {
    let mut type_param_counts: Vec<usize> = Vec::new();
    let mut imported_functions = 0usize;
    let mut globals = 0usize;
    let mut module_blocks = 0usize;
    let mut memories = 0usize;
    let mut tables = 0usize;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| ProfileError::Feature(e.to_string()))?;
        match payload {
            Payload::TypeSection(reader) => {
                for group in reader {
                    let group = group.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    for subtype in group.types() {
                        let params = match &subtype.composite_type.inner {
                            CompositeInnerType::Func(f) => f.params().len(),
                            _ => 0,
                        };
                        type_param_counts.push(params);
                    }
                }
                check(
                    type_param_counts.len(),
                    profile::MAX_TYPES_PER_MODULE,
                    "types per module",
                )?;
                if let Some(worst) = type_param_counts.iter().max() {
                    check(
                        *worst,
                        profile::MAX_PARAMS_PER_FUNCTION,
                        "params per function",
                    )?;
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    match import.ty {
                        TypeRef::Func(_) => imported_functions += 1,
                        TypeRef::Memory(_) => memories += 1,
                        TypeRef::Table(_) => tables += 1,
                        TypeRef::Global(_) => globals += 1,
                        TypeRef::Tag(_) => {}
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                check(
                    imported_functions + reader.count() as usize,
                    profile::MAX_FUNCTIONS_PER_MODULE,
                    "functions per module",
                )?;
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory = memory.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    memories += 1;
                    bounded_maximum(memory.maximum, profile::MAX_MEMORY_PAGES, "memory pages")?;
                }
                check(
                    memories,
                    profile::MAX_MEMORIES_PER_MODULE,
                    "memories per module",
                )?;
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table = table.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    tables += 1;
                    bounded_maximum(
                        table.ty.maximum,
                        profile::MAX_TABLE_ELEMENTS,
                        "table elements",
                    )?;
                }
                check(tables, profile::MAX_TABLES_PER_MODULE, "tables per module")?;
            }
            Payload::GlobalSection(reader) => {
                globals += reader.count() as usize;
                check(
                    globals,
                    profile::MAX_GLOBALS_PER_MODULE,
                    "globals per module",
                )?;
            }
            Payload::StartSection { .. } => return Err(ProfileError::StartSection),
            Payload::CodeSectionEntry(body) => {
                module_blocks += validate_function_body(&body)?;
                check(
                    module_blocks,
                    profile::MAX_BLOCKS_PER_MODULE,
                    "blocks per module",
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Checks one function body's structural limits; returns its block count for
/// the per-module total.
fn validate_function_body(body: &FunctionBody<'_>) -> Result<usize, ProfileError> {
    check(
        body.range().len(),
        profile::MAX_FUNCTION_BODY_BYTES,
        "function body bytes",
    )?;

    let mut locals = 0usize;
    let locals_reader = body
        .get_locals_reader()
        .map_err(|e| ProfileError::Feature(e.to_string()))?;
    for entry in locals_reader {
        let (count, _ty) = entry.map_err(|e| ProfileError::Feature(e.to_string()))?;
        locals += count as usize;
    }
    check(
        locals,
        profile::MAX_LOCALS_PER_FUNCTION,
        "locals per function",
    )?;

    let mut blocks = 0usize;
    let ops = body
        .get_operators_reader()
        .map_err(|e| ProfileError::Feature(e.to_string()))?;
    for op in ops {
        let op = op.map_err(|e| ProfileError::Feature(e.to_string()))?;
        if matches!(
            op,
            Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. }
        ) {
            blocks += 1;
        }
    }
    check(
        blocks,
        profile::MAX_BLOCKS_PER_FUNCTION,
        "blocks per function",
    )?;
    Ok(blocks)
}

/// A memory or table must declare a maximum, and it must be within bounds.
fn bounded_maximum(declared: Option<u64>, max: u64, what: &str) -> Result<(), ProfileError> {
    let declared = declared
        .ok_or_else(|| ProfileError::Structural(format!("{what} without a declared maximum")))?;
    if declared > max {
        return Err(ProfileError::Structural(format!(
            "{what} maximum of {declared} exceeds {max}"
        )));
    }
    Ok(())
}

fn check(actual: usize, max: usize, what: &str) -> Result<(), ProfileError> {
    if actual > max {
        return Err(ProfileError::Structural(format!(
            "{what}: {actual} > {max}"
        )));
    }
    Ok(())
}
