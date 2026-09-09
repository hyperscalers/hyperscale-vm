//! Component export shapes.
//!
//! A method's ABI binding says how each of the guest's arguments is
//! built; the artifact's export type says how many arguments there are
//! and what each one is. Nothing forces the two to agree — the binding
//! is authored metadata, the export type is compiled code — so whoever
//! admits a package judges one against the other, and this module is the
//! artifact half of that judgement: the parameter shapes of every
//! function the component exports, with handle parameters resolved to
//! the state resource they borrow, and whether the export can decline.

use std::collections::BTreeMap;

use hyperscale_vm_embed::abi::CoreType;
use wasmparser::component_types::{
    ComponentAnyTypeId, ComponentDefinedType, ComponentEntityType, ComponentValType, ResourceId,
};
use wasmparser::types::{Types, TypesRef};
use wasmparser::{
    BinaryReaderError, ComponentExternalKind, CompositeInnerType, ExternalKind, FuncType, Parser,
    Payload, PrimitiveValType, TypeRef, ValType, Validator,
};

use crate::validator::{ProfileError, profile_features};

/// One parameter of a component export, in the shapes the kernel world
/// can put there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportParam {
    /// `borrow<site>`: one declared access, whatever its width.
    Handle,
    /// `own<bucket>`: a value edge the call transfers into the guest.
    Bucket,
    /// `list<u8>`: keys, opaque values, and every other byte-shaped one.
    Bytes,
    /// A scalar `u64`.
    U64,
    /// A `bool`, which only a clause's guard verdict crosses as.
    Flag,
    /// The world's `address` record.
    Address,
    /// Anything else the world's grammar admits but no binding names.
    Other,
}

impl ExportParam {
    /// Whether the parameter takes a handle on something the kernel
    /// owns, rather than a value copied across the boundary.
    ///
    /// What separates a parameter only a capability binding can fill
    /// from one a derived value can. Exhaustive on purpose: a shape the
    /// world gains has to answer this before a binding can name it.
    #[must_use]
    pub const fn is_resource(&self) -> bool {
        match self {
            Self::Handle | Self::Bucket => true,
            Self::Bytes | Self::U64 | Self::Flag | Self::Address | Self::Other => false,
        }
    }
}

/// One export as the gate reads it: what it takes, and how it ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportShape {
    /// The parameter shapes, in the export's own order.
    pub params: Vec<ExportParam>,
    /// How many value edges the result carries: one own, the elements of
    /// a tuple of owns, or none.
    ///
    /// Judged against what the signature declares it produces, so a
    /// package cannot describe itself as yielding edges its code does not
    /// hand back.
    pub edges: usize,
    /// Whether the result carries a value beside its edges — the method
    /// answers with something a caller reads off the receipt.
    ///
    /// Judged against what the signature declares, so a package cannot
    /// describe itself as answering when its code hands nothing back, or
    /// stay silent about one it does.
    pub answers: bool,
    /// Whether the result carries an error arm — the method can decline
    /// on its own terms rather than only by trapping.
    ///
    /// The mark a signature declares is judged against this, so a
    /// package cannot describe itself as declining when its code has no
    /// way to, or as total when it has.
    pub declines: bool,
}

/// The shape of every function the component exports, by export name.
///
/// # Errors
///
/// [`ProfileError::Feature`] if the artifact does not validate under the
/// profile's feature set — callers run the full profile validator first,
/// so an error here means the artifact was never admitted at all.
pub fn component_exports(bytes: &[u8]) -> Result<BTreeMap<String, ExportShape>, ProfileError> {
    let types = Validator::new_with_features(profile_features())
        .validate_all(bytes)
        .map_err(|error| ProfileError::Feature(error.to_string()))?;
    classify_exports(bytes, &types)
}

/// As [`component_exports`], over types a validation already in hand
/// produced — how the publish gate reads the exports without validating
/// the same bytes twice.
///
/// # Errors
///
/// [`ProfileError::Feature`] if the export section does not parse, which
/// a validated artifact's cannot.
pub fn classify_exports(
    bytes: &[u8],
    types: &Types,
) -> Result<BTreeMap<String, ExportShape>, ProfileError> {
    let types = types.as_ref();
    let resources = state_resources(types);

    let mut out = BTreeMap::new();
    for name in export_names(bytes)? {
        let Some(item) = types.component_item_for_export(&name) else {
            continue;
        };
        let ComponentEntityType::Func(func) = item.ty else {
            continue;
        };
        let Some(ty) = types.get(func) else {
            continue;
        };
        let params = ty
            .params
            .iter()
            .map(|(_, param)| param_shape(types, &resources, param))
            .collect();
        let declines = ty.result.is_some_and(|result| declinable(types, &result));
        let edges = ty.result.map_or(0, |result| edge_count(types, &result));
        let answers = ty.result.is_some_and(|result| answered(types, &result));
        out.insert(
            name,
            ExportShape {
                params,
                edges,
                answers,
                declines,
            },
        );
    }
    Ok(out)
}

/// The state interface's resources, named as the interface exports them.
fn state_resources(types: TypesRef<'_>) -> BTreeMap<ResourceId, String> {
    let mut resources = BTreeMap::new();
    let Some(item) = types.component_item_for_import("hyperscale:kernel/state") else {
        return resources;
    };
    let ComponentEntityType::Instance(instance) = item.ty else {
        return resources;
    };
    let Some(instance) = types.get(instance) else {
        return resources;
    };
    for (name, export) in &instance.exports {
        if let ComponentEntityType::Type {
            referenced: ComponentAnyTypeId::Resource(resource),
            ..
        } = export.ty
        {
            resources.insert(resource.resource(), name.clone());
        }
    }
    resources
}

/// The outermost component's function export names, in declaration order.
/// A nested component's exports are its own, reachable through nothing a
/// manifest can name.
fn export_names(bytes: &[u8]) -> Result<Vec<String>, ProfileError> {
    let mut names = Vec::new();
    let mut depth = 0usize;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|error| ProfileError::Feature(error.to_string()))? {
            Payload::ModuleSection { .. } | Payload::ComponentSection { .. } => depth += 1,
            Payload::End(_) => depth = depth.saturating_sub(1),
            Payload::ComponentExportSection(reader) if depth == 0 => {
                for export in reader {
                    let export =
                        export.map_err(|error| ProfileError::Feature(error.to_string()))?;
                    if export.kind == ComponentExternalKind::Func {
                        names.push(export.name.name.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(names)
}

/// Whether a result type carries an error arm. The profile pins the
/// shape to `result<list<u8>, u32>` or `result<_, u32>`, so its presence
/// is the whole of what a reader needs.
fn declinable(types: TypesRef<'_>, result: &ComponentValType) -> bool {
    let ComponentValType::Type(id) = result else {
        return false;
    };
    matches!(types.get(*id), Some(ComponentDefinedType::Result { .. }))
}

/// Whether a result carries a byte list ahead of its edges, looking
/// through the refusal channel the way the edge count does.
///
/// A byte list is the one non-edge shape the convention admits in a
/// result, and it leads: the profile admits one nowhere else, and both
/// engines lift the run behind it as edges without looking at the count.
/// So the head is the whole of the question, and asking it of any other
/// position would have the gate admit a shape materialization refuses.
fn answered(types: TypesRef<'_>, result: &ComponentValType) -> bool {
    let ComponentValType::Type(id) = result else {
        return false;
    };
    match types.get(*id) {
        Some(ComponentDefinedType::List {
            element: ComponentValType::Primitive(PrimitiveValType::U8),
            ..
        }) => true,
        Some(ComponentDefinedType::Tuple(elements)) => elements
            .types
            .first()
            .is_some_and(|head| answered(types, head)),
        Some(ComponentDefinedType::Result { ok: Some(ok), .. }) => answered(types, ok),
        _ => false,
    }
}

/// How many owned edges a result carries, looking through the refusal
/// channel: an error arm says how a method ends, not what it produces.
fn edge_count(types: TypesRef<'_>, result: &ComponentValType) -> usize {
    let ComponentValType::Type(id) = result else {
        return 0;
    };
    match types.get(*id) {
        Some(ComponentDefinedType::Own(_)) => 1,
        Some(ComponentDefinedType::Tuple(elements)) => elements
            .types
            .iter()
            .filter(|ty| {
                matches!(ty, ComponentValType::Type(id)
                    if matches!(types.get(*id), Some(ComponentDefinedType::Own(_))))
            })
            .count(),
        Some(ComponentDefinedType::Result { ok: Some(ok), .. }) => edge_count(types, ok),
        _ => 0,
    }
}

/// The shape of one parameter.
fn param_shape(
    types: TypesRef<'_>,
    resources: &BTreeMap<ResourceId, String>,
    param: &ComponentValType,
) -> ExportParam {
    match param {
        ComponentValType::Primitive(PrimitiveValType::U64) => ExportParam::U64,
        ComponentValType::Primitive(PrimitiveValType::Bool) => ExportParam::Flag,
        ComponentValType::Type(id) => match types.get(*id) {
            Some(ComponentDefinedType::List {
                element: ComponentValType::Primitive(PrimitiveValType::U8),
                ..
            }) => ExportParam::Bytes,
            Some(ComponentDefinedType::Borrow(resource)) => resources
                .get(&resource.resource())
                .map_or(ExportParam::Other, |name| match name.as_str() {
                    "site" => ExportParam::Handle,
                    _ => ExportParam::Other,
                }),
            // An owned handle is a value edge: the world owns one such
            // resource, and a body that holds one holds value.
            Some(ComponentDefinedType::Own(_)) => ExportParam::Bucket,
            // The world's value records are told apart by their field
            // widths, which is what the profile admits them by: a record
            // of scalars, judged by shape rather than by the name an
            // interface happens to export it under.
            Some(ComponentDefinedType::Record(fields))
                if fields.fields.len() == 4
                    && fields.fields.iter().all(|(_, ty)| {
                        matches!(ty, ComponentValType::Primitive(PrimitiveValType::U64))
                    }) =>
            {
                ExportParam::Address
            }
            _ => ExportParam::Other,
        },
        ComponentValType::Primitive(_) => ExportParam::Other,
    }
}

/// One export of a core module, as the gate reads it: the core types it
/// takes, and whether it can decline.
///
/// What a core signature cannot say — which `i32` is a site, which a
/// bucket, which the length of a register argument — the binding says,
/// and the gate holds the binding's parameter kinds to these types
/// through [`ParamKind::core_type`](hyperscale_vm_embed::abi::ParamKind::core_type).
/// What it does not say either, how
/// many edges come back and whether an answer does, the walk holds the
/// reply to at run time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleExport {
    /// The parameter types, in the export's own order.
    pub params: Vec<CoreType>,
    /// Whether the export returns an `i32`: zero for completed, an
    /// error-table index plus one for a decline.
    pub declines: bool,
}

/// What the boundary pass reads off a core module: its function types,
/// its imports, the type of every function in index order, and its
/// exports.
pub(crate) struct ModuleScan {
    /// Function types by type index.
    pub types: Vec<FuncType>,
    /// Every import, in declaration order.
    pub imports: Vec<(String, String, TypeRef)>,
    /// The type index of every function, imports first.
    pub funcs: Vec<u32>,
    /// Every export, in declaration order.
    pub exports: Vec<(String, ExternalKind, u32)>,
}

impl ModuleScan {
    /// The function type of the function at `index` in the function
    /// index space.
    pub(crate) fn func_type(&self, index: u32) -> Option<&FuncType> {
        self.funcs
            .get(index as usize)
            .and_then(|ty| self.types.get(*ty as usize))
    }
}

/// Reads the sections the boundary pass judges.
///
/// # Errors
///
/// [`ProfileError::Feature`] where the bytes do not parse.
pub(crate) fn scan_module(bytes: &[u8]) -> Result<ModuleScan, ProfileError> {
    let feature = |error: BinaryReaderError| ProfileError::Feature(error.to_string());
    let mut scan = ModuleScan {
        types: Vec::new(),
        imports: Vec::new(),
        funcs: Vec::new(),
        exports: Vec::new(),
    };
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(feature)? {
            Payload::TypeSection(reader) => {
                for group in reader {
                    for sub in group.map_err(feature)?.into_types() {
                        scan.types.push(match sub.composite_type.inner {
                            CompositeInnerType::Func(func) => func,
                            _ => FuncType::new([], []),
                        });
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(feature)?;
                    if let TypeRef::Func(ty) | TypeRef::FuncExact(ty) = import.ty {
                        scan.funcs.push(ty);
                    }
                    scan.imports.push((
                        import.module.to_owned(),
                        import.name.to_owned(),
                        import.ty,
                    ));
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    scan.funcs.push(ty.map_err(feature)?);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(feature)?;
                    scan.exports
                        .push((export.name.to_owned(), export.kind, export.index));
                }
            }
            _ => {}
        }
    }
    Ok(scan)
}

/// The core type a value type is at the boundary.
pub(crate) const fn core_type(ty: ValType) -> Option<CoreType> {
    match ty {
        ValType::I32 => Some(CoreType::I32),
        ValType::I64 => Some(CoreType::I64),
        _ => None,
    }
}

/// The shape of every function a core module exports, by export name.
///
/// # Errors
///
/// [`ProfileError::Feature`] where the bytes do not parse, and
/// [`ProfileError::Boundary`] where an export's signature is outside
/// the convention — which [`validate_module`](crate::validate_module)
/// refuses, so an admitted module never reaches it.
pub fn module_exports(bytes: &[u8]) -> Result<BTreeMap<String, ModuleExport>, ProfileError> {
    let scan = scan_module(bytes)?;
    let mut out = BTreeMap::new();
    for (name, kind, index) in &scan.exports {
        if *kind != ExternalKind::Func {
            continue;
        }
        let ty = scan
            .func_type(*index)
            .ok_or_else(|| ProfileError::Boundary(format!("export `{name}` names no function")))?;
        let params = ty
            .params()
            .iter()
            .map(|param| {
                core_type(*param).ok_or_else(|| {
                    ProfileError::Boundary(format!(
                        "export `{name}` takes a {param:?}, which is not a boundary type"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let declines = match ty.results() {
            [] => false,
            [ValType::I32] => true,
            results => {
                return Err(ProfileError::Boundary(format!(
                    "export `{name}` returns {results:?}, where the convention admits nothing \
                     or one i32"
                )));
            }
        };
        out.insert(name.clone(), ModuleExport { params, declines });
    }
    Ok(out)
}
