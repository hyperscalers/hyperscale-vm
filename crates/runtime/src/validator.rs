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
    ComponentAlias, ComponentDefinedType, ComponentExternalKind, ComponentImportSectionReader,
    ComponentType, ComponentTypeRef, ComponentValType, CompositeInnerType, ConstExpr, DataKind,
    DataSectionReader, ElementItems, ElementKind, ElementSectionReader, FunctionBody,
    GlobalSectionReader, Operator, Parser, Payload, PrimitiveValType, TypeBounds, TypeRef,
    TypeSectionReader, ValType, Validator, WasmFeatures,
};

use crate::frames::{check_component_stack_bounds, check_stack_bounds};
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
        | WasmFeatures::COMPONENT_MODEL
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

    structural_pass(bytes)?;
    // The stack bound runs once over the whole component: a core module's
    // imports are wired to other modules' exports, and judging each module
    // alone would weigh those edges at zero.
    check_component_stack_bounds(bytes)
}

/// A value type the profile models, as a type-index slot records it.
///
/// Recorded per slot rather than as a flag because the vocabulary is no
/// longer uniform: a `result` arm is admissible where a value is
/// returned and nowhere else, so knowing that a slot holds *a* value type
/// stopped being enough to judge the position it appears in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueSlot {
    /// `u8`, `u32` or `u64`.
    Scalar,
    /// A record whose every field is a scalar.
    ///
    /// Admitted as a class rather than by naming the kernel's own types,
    /// because what the profile is judging is the property: such a record
    /// flattens to its fields, so it crosses in registers and reaches no
    /// linear memory. A record with a field the profile does not model is
    /// refused by the same walk that models the field.
    Flat,
    /// `list<u8>`.
    Bytes,
    /// `list<u64>`: the one non-byte list the world names, carrying a
    /// set of non-fungible instance ids. Admitted as its own slot rather
    /// than by widening the byte one, because the element width is what
    /// each engine's lowering turns on.
    Ids,
    /// `borrow<R>` of a state resource.
    Handle,
    /// `own<R>` of a state resource: a handle the guest holds rather than
    /// one lent to it for a call, so one it can keep, return, or discard.
    Owned,
    /// A tuple whose every element is an owned handle.
    ///
    /// A method's edges are its results, and a signature carries one
    /// result — so a method producing more than one edge produces them
    /// together. Admitted on the same property the flat records are: a
    /// tuple of handles is a run of `i32`s, so it costs the return area
    /// its own width and reaches linear memory for nothing else.
    OwnedTuple,
    /// `result<list<u8>, u32>` or `result<_, u32>`: the declared refusal
    /// channel.
    Declinable,
}

/// What a value type resolves to, or `None` where the profile models
/// nothing of the kind.
fn resolve(defined: &[Option<ValueSlot>], vt: ComponentValType) -> Option<ValueSlot> {
    match vt {
        ComponentValType::Primitive(
            PrimitiveValType::U8 | PrimitiveValType::U32 | PrimitiveValType::U64,
        ) => Some(ValueSlot::Scalar),
        ComponentValType::Type(index) => usize::try_from(index)
            .ok()
            .and_then(|index| defined.get(index).copied())
            .flatten(),
        ComponentValType::Primitive(_) => None,
    }
}

/// Whether a value type may occupy a parameter position.
///
/// The refusal channel is deliberately absent. It says how a method
/// *ends*, and a method that took one would be a caller handling a
/// callee's refusal — the shape A1 refuses at the manifest layer, which
/// the call boundary should not quietly reopen.
fn admits_param_type(defined: &[Option<ValueSlot>], vt: ComponentValType) -> bool {
    matches!(
        resolve(defined, vt),
        Some(
            ValueSlot::Scalar
                | ValueSlot::Flat
                | ValueSlot::Bytes
                | ValueSlot::Ids
                | ValueSlot::Handle
                | ValueSlot::Owned
        )
    )
}

/// Whether a value type may occupy an export's result position:
/// everything a parameter admits, plus the refusal channel and the tuple
/// a multi-edge method returns.
fn admits_result_type(defined: &[Option<ValueSlot>], vt: ComponentValType) -> bool {
    resolve(defined, vt).is_some()
}

/// Records one component type entry, resolving what its type-index slot
/// holds. The walk mirrors the executable spec's type index space —
/// declared types, then world-level `use` imports, aliases, and re-exports
/// — because a function type resolves its parameters through it.
fn record_component_type(
    defined: &mut Vec<Option<ValueSlot>>,
    entry: &ComponentType<'_>,
) -> Result<(), ProfileError> {
    let slot = match entry {
        ComponentType::Func(f) => {
            for (_, vt) in &*f.params {
                if !admits_param_type(defined, *vt) {
                    return Err(ProfileError::Structural(
                        "component parameter type is outside the profile vocabulary".to_string(),
                    ));
                }
            }
            if let Some(vt) = f.result
                && !admits_result_type(defined, vt)
            {
                return Err(ProfileError::Structural(
                    "component result type is outside the profile vocabulary".to_string(),
                ));
            }
            None
        }
        ComponentType::Defined(ComponentDefinedType::List(element)) => match element {
            ComponentValType::Primitive(PrimitiveValType::U8) => Some(ValueSlot::Bytes),
            ComponentValType::Primitive(PrimitiveValType::U64) => Some(ValueSlot::Ids),
            _ => {
                return Err(ProfileError::Structural(
                    "only list<u8> and list<u64> are within the profile".to_string(),
                ));
            }
        },
        ComponentType::Defined(ComponentDefinedType::Record(fields)) => {
            for (_, vt) in &**fields {
                if !matches!(resolve(defined, *vt), Some(ValueSlot::Scalar)) {
                    return Err(ProfileError::Structural(
                        "a record's fields must be scalars: what admits one is that it \
                         flattens rather than crossing through memory"
                            .to_string(),
                    ));
                }
            }
            Some(ValueSlot::Flat)
        }
        ComponentType::Defined(ComponentDefinedType::Borrow(_)) => Some(ValueSlot::Handle),
        ComponentType::Defined(ComponentDefinedType::Own(_)) => Some(ValueSlot::Owned),
        ComponentType::Defined(ComponentDefinedType::Tuple(elements)) => {
            for element in &**elements {
                if !matches!(resolve(defined, *element), Some(ValueSlot::Owned)) {
                    return Err(ProfileError::Structural(
                        "only a tuple of owned handles is within the profile: it is how a \
                         method with more than one edge returns them"
                            .to_string(),
                    ));
                }
            }
            Some(ValueSlot::OwnedTuple)
        }
        // The refusal channel, pinned to one shape. A code rather than a
        // payload, and the same code width whatever the method returns,
        // so what a receipt records is an index into the package's error
        // table and never author-chosen bytes.
        ComponentType::Defined(ComponentDefinedType::Result { ok, err }) => {
            if !matches!(
                err,
                Some(ComponentValType::Primitive(PrimitiveValType::U32))
            ) {
                return Err(ProfileError::Structural(
                    "a result's error arm must be u32, the package's error-table index".to_string(),
                ));
            }
            // The ok arm is whatever a method that cannot decline would
            // have returned: its edges, or nothing. An error arm says how
            // a method ends, and says nothing about what it produces.
            match ok.map(|vt| resolve(defined, vt)) {
                None | Some(Some(ValueSlot::Bytes | ValueSlot::Owned | ValueSlot::OwnedTuple)) => {
                    Some(ValueSlot::Declinable)
                }
                _ => {
                    return Err(ProfileError::Structural(
                        "a result's ok arm carries what the method produces: its edges, \
                         a byte list, or nothing"
                            .to_string(),
                    ));
                }
            }
        }
        _ => None,
    };
    defined.push(slot);
    Ok(())
}

/// Validates a bare core module against the deterministic profile.
///
/// The component path reaches the same structural pass through
/// [`validate_component`]; this entry exists so a core module can be
/// judged on its own — which is what lets the differential lanes assert
/// that everything the profile admits has an executable-spec witness.
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

/// Gates component imports to the kernel world and tracks the type-index
/// slot a world-level `use` takes.
fn check_component_imports(
    reader: ComponentImportSectionReader<'_>,
    defined: &mut Vec<Option<ValueSlot>>,
) -> Result<(), ProfileError> {
    for import in reader {
        let import = import.map_err(|e| ProfileError::Feature(e.to_string()))?;
        let name = import.name.name;
        // Type imports confer no capability — they are how a world's own
        // types encode, whether `use`d from an interface or declared in
        // the world itself — so only value-carrying imports are gated.
        // They do take a type-index slot, and an equality import carries
        // whatever the type it equals holds: a world-declared record
        // reaches its export's signature through one of these, so
        // dropping the slot would put every such export outside the
        // vocabulary.
        if let ComponentTypeRef::Type(bound) = import.ty {
            let equals = match bound {
                TypeBounds::Eq(index) => usize::try_from(index)
                    .ok()
                    .and_then(|index| defined.get(index).copied())
                    .flatten(),
                // A resource bound names a type with no representation of
                // its own; what a body can do with one is fixed by the
                // borrow types the interface exports.
                TypeBounds::SubResource => None,
            };
            defined.push(equals);
            continue;
        }
        if !name.starts_with(profile::KERNEL_IMPORT_PREFIX) {
            return Err(ProfileError::ForbiddenImport(name.to_string()));
        }
    }
    Ok(())
}

fn structural_pass(bytes: &[u8]) -> Result<(), ProfileError> {
    let mut core_modules = 0usize;
    // Type-index slots, by what each one holds.
    let mut defined: Vec<Option<ValueSlot>> = Vec::new();
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
                core_structural_pass(&bytes[unchecked_range])?;
            }
            Payload::ComponentSection { .. } => return Err(ProfileError::NestedComponent),
            Payload::ComponentTypeSection(reader) => {
                for entry in reader {
                    let entry = entry.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    record_component_type(&mut defined, &entry)?;
                }
            }
            Payload::ComponentImportSection(reader) => {
                check_component_imports(reader, &mut defined)?;
            }
            Payload::ComponentAliasSection(reader) => {
                for alias in reader {
                    let alias = alias.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if matches!(
                        alias,
                        ComponentAlias::InstanceExport {
                            kind: ComponentExternalKind::Type,
                            ..
                        }
                    ) {
                        defined.push(None);
                    }
                }
            }
            Payload::ComponentExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if export.kind == ComponentExternalKind::Type {
                        let aliased = usize::try_from(export.index)
                            .ok()
                            .and_then(|index| defined.get(index).copied())
                            .flatten();
                        defined.push(aliased);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn core_structural_pass(bytes: &[u8]) -> Result<(), ProfileError> {
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
                check_types(reader, &mut type_param_counts)?;
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    check_import(
                        &import.ty,
                        &mut imported_functions,
                        &mut memories,
                        &mut tables,
                    )?;
                }
                check(
                    memories,
                    profile::MAX_MEMORIES_PER_MODULE,
                    "memories per module",
                )?;
                check(tables, profile::MAX_TABLES_PER_MODULE, "tables per module")?;
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
                globals += check_globals(reader)?;
                check(
                    globals,
                    profile::MAX_GLOBALS_PER_MODULE,
                    "globals per module",
                )?;
            }
            Payload::DataSection(reader) => check_data_segments(reader)?,
            Payload::ElementSection(reader) => check_element_segments(reader)?,
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
/// carry the same maximum bounds as declared ones. A global or tag import
/// has no executable-spec witness, so it is a profile violation rather
/// than a counted item.
fn check_import(
    ty: &TypeRef,
    imported_functions: &mut usize,
    memories: &mut usize,
    tables: &mut usize,
) -> Result<(), ProfileError> {
    match ty {
        TypeRef::Func(_) | TypeRef::FuncExact(_) => *imported_functions += 1,
        TypeRef::Memory(memory) => {
            *memories += 1;
            bounded_maximum(memory.maximum, profile::MAX_MEMORY_PAGES, "memory pages")?;
        }
        TypeRef::Table(table) => {
            *tables += 1;
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

/// Data segments are active with constant offsets: the spec applies them
/// at instantiation and models no other form.
fn check_data_segments(reader: DataSectionReader<'_>) -> Result<(), ProfileError> {
    for data in reader {
        let data = data.map_err(|e| ProfileError::Feature(e.to_string()))?;
        let DataKind::Active { offset_expr, .. } = &data.kind else {
            return Err(ProfileError::Structural(
                "passive data segments are outside the profile".to_string(),
            ));
        };
        check_const_expr(offset_expr, "data segment")?;
    }
    Ok(())
}

/// Element segments are active, constant-offset, and function-indexed.
fn check_element_segments(reader: ElementSectionReader<'_>) -> Result<(), ProfileError> {
    for element in reader {
        let element = element.map_err(|e| ProfileError::Feature(e.to_string()))?;
        let ElementKind::Active { offset_expr, .. } = &element.kind else {
            return Err(ProfileError::Structural(
                "passive element segments are outside the profile".to_string(),
            ));
        };
        check_const_expr(offset_expr, "element segment")?;
        if !matches!(element.items, ElementItems::Functions(_)) {
            return Err(ProfileError::Structural(
                "expression element segments are outside the profile".to_string(),
            ));
        }
    }
    Ok(())
}

/// A constant expression is exactly one integer constant and its `end`.
///
/// The operator blocklist walks function bodies, and a global initializer
/// or a segment offset is neither — but the executable spec evaluates
/// const expressions with the same integer-only vocabulary, so anything
/// richer (a reference, an extended-const computation) is admitted here
/// and unexecutable there.
fn check_const_expr(expr: &ConstExpr<'_>, what: &str) -> Result<(), ProfileError> {
    let outside = || ProfileError::Structural(format!("{what} initializer is outside the profile"));
    let mut reader = expr.get_operators_reader();
    let first = reader
        .read()
        .map_err(|e| ProfileError::Feature(e.to_string()))?;
    if !matches!(first, Operator::I32Const { .. } | Operator::I64Const { .. }) {
        return Err(outside());
    }
    match reader
        .read()
        .map_err(|e| ProfileError::Feature(e.to_string()))?
    {
        Operator::End => Ok(()),
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
