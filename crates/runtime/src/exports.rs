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

use hyperscale_vm_types::CellKind;
use wasmparser::component_types::{
    ComponentAnyTypeId, ComponentDefinedType, ComponentEntityType, ComponentValType, ResourceId,
};
use wasmparser::types::{Types, TypesRef};
use wasmparser::{ComponentExternalKind, Parser, Payload, PrimitiveValType, Validator};

use crate::validator::{ProfileError, profile_features};

/// One parameter of a component export, in the shapes the kernel world
/// can put there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportParam {
    /// `borrow<R>` of a state cell, at the kind whose world type the
    /// `hyperscale:kernel/state` interface exports it as — one
    /// correspondence, [`CellKind::world_type`]'s own.
    Handle(CellKind),
    /// `borrow<issuer>`: this invocation's authority to create value.
    Issuer,
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
        out.insert(
            name,
            ExportShape {
                params,
                edges,
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
                    "issuer" => ExportParam::Issuer,
                    named => CellKind::from_world_type(named)
                        .map_or(ExportParam::Other, ExportParam::Handle),
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
