//! Component export parameter shapes.
//!
//! A method's ABI binding says how each of the guest's arguments is
//! built; the artifact's export type says how many arguments there are
//! and what each one is. Nothing forces the two to agree — the binding
//! is authored metadata, the export type is compiled code — so whoever
//! admits a package judges one against the other, and this module is the
//! artifact half of that judgement: the parameter shapes of every
//! function the component exports, with handle parameters resolved to
//! the state resource they borrow.

use std::collections::BTreeMap;

use wasmparser::component_types::{
    ComponentAnyTypeId, ComponentDefinedType, ComponentEntityType, ComponentValType, ResourceId,
};
use wasmparser::types::TypesRef;
use wasmparser::{ComponentExternalKind, Parser, Payload, PrimitiveValType, Validator};

use crate::validator::{ProfileError, profile_features};

/// One parameter of a component export, in the shapes the kernel world
/// can put there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportParam {
    /// `borrow<R>` of a state resource, named as the
    /// `hyperscale:kernel/state` interface exports it — `"read-cell"`,
    /// `"write-cell"`, and so on.
    Handle(String),
    /// `list<u8>`: amount cells, keys, and every other byte-shaped value.
    Bytes,
    /// A scalar `u64`.
    U64,
    /// Anything else the world's grammar admits but no binding names.
    Other,
}

/// The parameter shapes of every function the component exports, by
/// export name.
///
/// # Errors
///
/// [`ProfileError::Feature`] if the artifact does not validate under the
/// profile's feature set — callers run the full profile validator first,
/// so an error here means the artifact was never admitted at all.
pub fn component_export_params(
    bytes: &[u8],
) -> Result<BTreeMap<String, Vec<ExportParam>>, ProfileError> {
    let types = Validator::new_with_features(profile_features())
        .validate_all(bytes)
        .map_err(|error| ProfileError::Feature(error.to_string()))?;
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
        out.insert(name, params);
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

/// The shape of one parameter.
fn param_shape(
    types: TypesRef<'_>,
    resources: &BTreeMap<ResourceId, String>,
    param: &ComponentValType,
) -> ExportParam {
    match param {
        ComponentValType::Primitive(PrimitiveValType::U64) => ExportParam::U64,
        ComponentValType::Type(id) => match types.get(*id) {
            Some(ComponentDefinedType::List {
                element: ComponentValType::Primitive(PrimitiveValType::U8),
                ..
            }) => ExportParam::Bytes,
            Some(ComponentDefinedType::Borrow(resource)) => resources
                .get(&resource.resource())
                .map_or(ExportParam::Other, |name| ExportParam::Handle(name.clone())),
            _ => ExportParam::Other,
        },
        ComponentValType::Primitive(_) => ExportParam::Other,
    }
}
