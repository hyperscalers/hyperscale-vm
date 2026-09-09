//! Module export shapes.
//!
//! A method's ABI binding says how each of the guest's arguments is
//! built; the module's export type says how many arguments there are and
//! what width each one is. Nothing forces the two to agree — the binding
//! is authored metadata, the export type is compiled code — so whoever
//! admits a package judges one against the other, and this module is the
//! artifact half of that judgement.

use std::collections::BTreeMap;

use hyperscale_vm_embed::abi::CoreType;
use wasmparser::{
    BinaryReaderError, CompositeInnerType, ExternalKind, FuncType, Parser, Payload, TypeRef,
    ValType,
};

use crate::validator::ProfileError;

/// One export, as the gate reads it: the core types it
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

/// The shape of every function the module exports, by export name.
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
