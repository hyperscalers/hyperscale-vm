//! Deploy-time profile validation.
//!
//! A module is validated once, before it enters state; a non-conforming
//! artifact never deploys. Three passes: wasmparser's validator under the
//! profile's feature set (rejecting floats, SIMD, threads, exceptions,
//! tail calls, memory64 and GC), a structural pass enforcing the
//! [`crate::profile`] limits, and the boundary pass holding the module's
//! imports and exports to what the kernel defines.

use hyperscale_vm_embed::abi::{CoreType, IMPORTS, MEMORY};
use thiserror::Error;
use wasmparser::{
    CompositeInnerType, ConstExpr, DataKind, DataSectionReader, ElementItems, ElementKind,
    ElementSectionReader, ExternalKind, FunctionBody, GlobalSectionReader, Operator, Parser,
    Payload, TypeRef, TypeSectionReader, ValType, Validator, WasmFeatures,
};

use crate::exports::{core_type, scan_module};
use crate::frames::check_stack_bounds;
use crate::profile;

/// A profile violation. Every variant is a deterministic deploy-time verdict.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// The artifact exceeds [`profile::MAX_ARTIFACT_BYTES`].
    #[error("artifact of {actual} bytes exceeds the {max}-byte limit")]
    ArtifactTooLarge {
        /// Artifact size.
        actual: usize,
        /// The limit it exceeds.
        max: usize,
    },
    /// Rejected by validation under the profile feature set.
    #[error("outside the profile feature set: {0}")]
    Feature(String),
    /// An import the kernel does not define.
    #[error("import outside the kernel: {0}")]
    ForbiddenImport(String),
    /// A start section; instantiation must be inert.
    #[error("start sections are not permitted")]
    StartSection,
    /// A structural limit exceeded; the message names the limit.
    #[error("structural limit exceeded: {0}")]
    Structural(String),
    /// A module outside the boundary convention: an import the kernel
    /// does not define or at a type it does not, an export the kernel
    /// cannot call, or a memory the kernel cannot reach.
    #[error("outside the boundary convention: {0}")]
    Boundary(String),
}

/// The profile's wasm feature set, as an explicit allowlist. Everything
/// admitted here has an executable-spec witness in vm-ref; a proposal a
/// parser bump turns on by default stays out until deliberately added here.
///
/// A feature left out is refused during validation, which is a stronger
/// place to refuse than the operator walk: the walk sees function bodies,
/// so it can reject an operator but not a type in a signature or a local.
/// Typed function references are the case that proves it — blocking
/// `call_ref` alone would still admit `(ref null $t)` in value position,
/// which the spec has no decoding for. Bulk memory's table operations and
/// the reference-types operators are the exceptions: their features stay
/// on for `memory.copy`/`memory.fill` and the `call_indirect` encoding, and
/// the operator walk excludes the rest.
pub(crate) fn profile_features() -> WasmFeatures {
    WasmFeatures::MUTABLE_GLOBAL
        | WasmFeatures::SATURATING_FLOAT_TO_INT
        | WasmFeatures::SIGN_EXTENSION
        | WasmFeatures::MULTI_VALUE
        | WasmFeatures::REFERENCE_TYPES
        | WasmFeatures::CALL_INDIRECT_OVERLONG
        | WasmFeatures::BULK_MEMORY
        | WasmFeatures::BULK_MEMORY_OPT
}

/// Validates a bare core module against the deterministic profile.
///
/// The feature set, the structural limits and the stack bound, without
/// the boundary convention: what lets the differential lanes assert that
/// everything the profile admits has an executable-spec witness, over
/// modules that import nothing and export whatever they like.
///
/// # Errors
///
/// Returns the first [`ProfileError`] encountered; verdicts are
/// deterministic functions of the bytes.
pub fn validate_core_module(bytes: &[u8]) -> Result<(), ProfileError> {
    Validator::new_with_features(profile_features())
        .validate_all(bytes)
        .map_err(|e| ProfileError::Feature(e.to_string()))?;
    core_structural_pass(bytes)?;
    check_stack_bounds(bytes)
}

/// Validates a core module the kernel calls directly.
///
/// The profile's feature set and structural limits, then the boundary
/// convention: every import is one the kernel defines, at the type it
/// defines it; the module exports exactly one memory, named as the
/// kernel reads it, and every other export is a function the kernel can
/// call — boundary-typed parameters, and nothing or one `i32` back.
/// Then the stack bound, over one module and one chain.
///
/// # Errors
///
/// Returns the first [`ProfileError`] encountered; verdicts are
/// deterministic functions of the bytes.
pub fn validate_module(bytes: &[u8]) -> Result<(), ProfileError> {
    if bytes.len() > profile::MAX_ARTIFACT_BYTES {
        return Err(ProfileError::ArtifactTooLarge {
            actual: bytes.len(),
            max: profile::MAX_ARTIFACT_BYTES,
        });
    }
    Validator::new_with_features(profile_features())
        .validate_all(bytes)
        .map_err(|e| ProfileError::Feature(e.to_string()))?;
    core_structural_pass(bytes)?;
    boundary_pass(bytes)?;
    check_stack_bounds(bytes)
}

/// The boundary convention over a parsed module.
fn boundary_pass(bytes: &[u8]) -> Result<(), ProfileError> {
    let scan = scan_module(bytes)?;
    let boundary = |what: String| ProfileError::Boundary(what);

    let mut imported_funcs = 0u32;
    for (module, name, ty) in &scan.imports {
        let (TypeRef::Func(ty) | TypeRef::FuncExact(ty)) = ty else {
            return Err(boundary(format!(
                "`{module}` `{name}`: the kernel imports nothing but functions"
            )));
        };
        let Some((_, _, params, results)) =
            IMPORTS.iter().find(|(m, n, _, _)| m == module && n == name)
        else {
            return Err(ProfileError::ForbiddenImport(format!("{module}/{name}")));
        };
        let declared = scan
            .types
            .get(*ty as usize)
            .ok_or_else(|| boundary(format!("`{module}` `{name}` names no type")))?;
        let same = |declared: &[ValType], defined: &[CoreType]| {
            declared.len() == defined.len()
                && declared
                    .iter()
                    .zip(defined)
                    .all(|(d, e)| core_type(*d) == Some(*e))
        };
        if !same(declared.params(), params) || !same(declared.results(), results) {
            return Err(boundary(format!(
                "`{module}` `{name}` is imported at {declared:?}, not the type the kernel \
                 defines it at"
            )));
        }
        imported_funcs += 1;
    }

    let mut memories = 0usize;
    for (name, kind, index) in &scan.exports {
        match kind {
            ExternalKind::Memory => {
                if name != MEMORY {
                    return Err(boundary(format!(
                        "memory exported as `{name}`; the kernel reads `{MEMORY}`"
                    )));
                }
                memories += 1;
            }
            ExternalKind::Func => {
                if *index < imported_funcs {
                    return Err(boundary(format!("export `{name}` re-exports an import")));
                }
                let ty = scan
                    .func_type(*index)
                    .ok_or_else(|| boundary(format!("export `{name}` names no function")))?;
                if ty.params().iter().any(|param| core_type(*param).is_none()) {
                    return Err(boundary(format!(
                        "export `{name}` takes {:?}; the boundary carries i32 and i64",
                        ty.params()
                    )));
                }
                if !matches!(ty.results(), [] | [ValType::I32]) {
                    return Err(boundary(format!(
                        "export `{name}` returns {:?}; an export returns nothing or one i32",
                        ty.results()
                    )));
                }
            }
            _ => {
                return Err(boundary(format!(
                    "export `{name}` is a {kind:?}; the kernel reads functions and one memory"
                )));
            }
        }
    }
    if memories != 1 {
        return Err(boundary(format!(
            "{memories} memories exported; the kernel reads exactly one, `{MEMORY}`"
        )));
    }
    Ok(())
}

fn core_structural_pass(bytes: &[u8]) -> Result<(), ProfileError> {
    let mut type_param_counts: Vec<usize> = Vec::new();
    let mut imported_functions = 0usize;
    let mut globals = 0usize;
    let mut module_blocks = 0usize;
    // One minimum per memory or table, imported or declared; the per-module
    // count limits hold each list to at most one entry, and segment bounds
    // are judged against the front. Sections arrive in index order, so the
    // minima are recorded before any segment reads them.
    let mut memory_min_pages: Vec<u64> = Vec::new();
    let mut table_min_elements: Vec<u64> = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| ProfileError::Feature(e.to_string()))?;
        match payload {
            Payload::TypeSection(reader) => {
                check_types(reader, &mut type_param_counts)?;
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    check_import(
                        &import.ty,
                        &mut imported_functions,
                        &mut memory_min_pages,
                        &mut table_min_elements,
                    )?;
                }
                check(
                    memory_min_pages.len(),
                    profile::MAX_MEMORIES_PER_MODULE,
                    "memories per module",
                )?;
                check(
                    table_min_elements.len(),
                    profile::MAX_TABLES_PER_MODULE,
                    "tables per module",
                )?;
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
                    memory_min_pages.push(memory.initial);
                    bounded_maximum(memory.maximum, profile::MAX_MEMORY_PAGES, "memory pages")?;
                }
                check(
                    memory_min_pages.len(),
                    profile::MAX_MEMORIES_PER_MODULE,
                    "memories per module",
                )?;
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table = table.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    table_min_elements.push(table.ty.initial);
                    bounded_maximum(
                        table.ty.maximum,
                        profile::MAX_TABLE_ELEMENTS,
                        "table elements",
                    )?;
                }
                check(
                    table_min_elements.len(),
                    profile::MAX_TABLES_PER_MODULE,
                    "tables per module",
                )?;
            }
            Payload::GlobalSection(reader) => {
                globals += check_globals(reader)?;
                check(
                    globals,
                    profile::MAX_GLOBALS_PER_MODULE,
                    "globals per module",
                )?;
            }
            Payload::DataSection(reader) => {
                check_data_segments(reader, memory_min_pages.first().copied().unwrap_or(0))?;
            }
            Payload::ElementSection(reader) => {
                check_element_segments(reader, table_min_elements.first().copied().unwrap_or(0))?;
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

/// Checks the type section's counts: types per module and the worst
/// per-function parameter count.
fn check_types(
    reader: TypeSectionReader<'_>,
    type_param_counts: &mut Vec<usize>,
) -> Result<(), ProfileError> {
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
    Ok(())
}

/// Counts one import into the per-kind totals; imported memories and tables
/// carry the same maximum bounds as declared ones, and record their minima
/// for the segment bounds. A global or tag import has no executable-spec
/// witness, so it is a profile violation rather than a counted item.
fn check_import(
    ty: &TypeRef,
    imported_functions: &mut usize,
    memory_min_pages: &mut Vec<u64>,
    table_min_elements: &mut Vec<u64>,
) -> Result<(), ProfileError> {
    match ty {
        TypeRef::Func(_) | TypeRef::FuncExact(_) => *imported_functions += 1,
        TypeRef::Memory(memory) => {
            memory_min_pages.push(memory.initial);
            bounded_maximum(memory.maximum, profile::MAX_MEMORY_PAGES, "memory pages")?;
        }
        TypeRef::Table(table) => {
            table_min_elements.push(table.initial);
            bounded_maximum(table.maximum, profile::MAX_TABLE_ELEMENTS, "table elements")?;
        }
        TypeRef::Global(_) | TypeRef::Tag(_) => {
            return Err(ProfileError::Structural(
                "only function, memory, and table imports are within the profile".to_string(),
            ));
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
        // Bulk memory's table and passive-segment operations, and
        // reference-types' operators, have no vm-ref witness; the features
        // stay enabled only for memory.copy/fill and the call_indirect
        // encoding.
        if matches!(
            op,
            Operator::TableCopy { .. }
                | Operator::TableInit { .. }
                | Operator::ElemDrop { .. }
                | Operator::TableGet { .. }
                | Operator::TableSet { .. }
                | Operator::TableGrow { .. }
                | Operator::TableSize { .. }
                | Operator::TableFill { .. }
                | Operator::MemoryInit { .. }
                | Operator::DataDrop { .. }
                | Operator::RefNull { .. }
                | Operator::RefIsNull
                | Operator::RefFunc { .. }
        ) {
            return Err(ProfileError::Feature(
                "table, passive-segment, and reference operators are outside the profile"
                    .to_string(),
            ));
        }
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

/// Globals are integer-typed with constant initializers; returns how many
/// this section declares.
fn check_globals(reader: GlobalSectionReader<'_>) -> Result<usize, ProfileError> {
    let mut globals = 0usize;
    for global in reader {
        let global = global.map_err(|e| ProfileError::Feature(e.to_string()))?;
        if !matches!(global.ty.content_type, ValType::I32 | ValType::I64) {
            return Err(ProfileError::Structural(
                "only i32 and i64 globals are within the profile".to_string(),
            ));
        }
        check_const_expr(&global.init_expr, "global")?;
        globals += 1;
    }
    Ok(globals)
}

/// Bytes per wasm linear-memory page.
const WASM_PAGE_BYTES: u64 = 64 * 1024;

/// Data segments are active, constant-offset, and land inside the memory
/// minimum: the spec applies them at instantiation and models no other
/// form, and a segment past the minimum would trap every instantiation.
fn check_data_segments(
    reader: DataSectionReader<'_>,
    memory_min_pages: u64,
) -> Result<(), ProfileError> {
    let memory_bytes = memory_min_pages * WASM_PAGE_BYTES;
    for data in reader {
        let data = data.map_err(|e| ProfileError::Feature(e.to_string()))?;
        let DataKind::Active { offset_expr, .. } = &data.kind else {
            return Err(ProfileError::Structural(
                "passive data segments are outside the profile".to_string(),
            ));
        };
        let offset = check_const_expr(offset_expr, "data segment")?;
        let end = offset.saturating_add(data.data.len() as u64);
        if end > memory_bytes {
            return Err(ProfileError::Structural(format!(
                "data segment ends at byte {end}, past the {memory_bytes}-byte memory minimum"
            )));
        }
    }
    Ok(())
}

/// Element segments are active, constant-offset, function-indexed, and
/// land inside the table minimum, so applying them cannot trap.
fn check_element_segments(
    reader: ElementSectionReader<'_>,
    table_min_elements: u64,
) -> Result<(), ProfileError> {
    for element in reader {
        let element = element.map_err(|e| ProfileError::Feature(e.to_string()))?;
        let ElementKind::Active { offset_expr, .. } = &element.kind else {
            return Err(ProfileError::Structural(
                "passive element segments are outside the profile".to_string(),
            ));
        };
        let offset = check_const_expr(offset_expr, "element segment")?;
        let ElementItems::Functions(functions) = &element.items else {
            return Err(ProfileError::Structural(
                "expression element segments are outside the profile".to_string(),
            ));
        };
        let end = offset.saturating_add(u64::from(functions.count()));
        if end > table_min_elements {
            return Err(ProfileError::Structural(format!(
                "element segment ends at index {end}, past the {table_min_elements}-element \
                 table minimum"
            )));
        }
    }
    Ok(())
}

/// A constant expression is exactly one integer constant and its `end`;
/// returns the constant's unsigned value (an i32 reads as u32, which is
/// how a segment offset consumes it).
///
/// The operator blocklist walks function bodies, and a global initializer
/// or a segment offset is neither — but the executable spec evaluates
/// const expressions with the same integer-only vocabulary, so anything
/// richer (a reference, an extended-const computation) is admitted here
/// and unexecutable there.
fn check_const_expr(expr: &ConstExpr<'_>, what: &str) -> Result<u64, ProfileError> {
    let outside = || ProfileError::Structural(format!("{what} initializer is outside the profile"));
    let mut reader = expr.get_operators_reader();
    let value = match reader
        .read()
        .map_err(|e| ProfileError::Feature(e.to_string()))?
    {
        Operator::I32Const { value } => u64::from(value.cast_unsigned()),
        Operator::I64Const { value } => value.cast_unsigned(),
        _ => return Err(outside()),
    };
    match reader
        .read()
        .map_err(|e| ProfileError::Feature(e.to_string()))?
    {
        Operator::End => Ok(value),
        _ => Err(outside()),
    }
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
