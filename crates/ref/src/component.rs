//! The component layer: decode, instantiation, and the canonical ABI for the
//! kernel world.
//!
//! Scope is the contract shape the profile admits: one component, core
//! modules linked through core instances, imports drawn from the
//! `hyperscale:kernel` interfaces, canon lower/lift with memory+realloc
//! options, and resource handles with call-scoped borrows. The kernel
//! interfaces' semantics are wired directly against [`RefKernelHost`] — the
//! world is fixed, so its ABI is implemented explicitly rather than derived
//! from types.
//!
//! The ABI's control rules are modelled alongside its data rules: a borrow
//! is live only for the call that lowered it, and the instance may not be
//! left from inside a canonical-ABI callback (`may_leave`). A rule the
//! blessed engine enforces and this crate does not is a divergence the
//! differential lanes cannot see, because the spec is what says what the
//! artifact means.

use std::collections::HashMap;

use hyperscale_vm_types::AbortReason;
use wasmparser::{
    CanonicalFunction, CanonicalOption, ComponentAlias, ComponentDefinedType,
    ComponentExternalKind, ComponentType, ComponentTypeRef, ComponentValType, ExternalKind,
    Instance as CoreInstanceReader, InstantiationArgKind, Parser, Payload, PrimitiveValType,
    TypeBounds,
};

use crate::error::{DecodeError, Trap};
use crate::interp::{
    CanonDispatch, CanonError, ExecError, FuncAddr, Memory, Store, call, instantiate_module,
};
use crate::module::{CoreImportKind, RefModule};
use crate::ops::Value;

/// The host surface behind the kernel world.
///
/// Mirrors the runtime's trait — same operations, same deterministic
/// refusals — so one host drives both implementations. Every `Err` is a
/// kernel refusal that traps with the class the host assigned it; the
/// boundary transports that class and never words one of its own.
#[allow(missing_docs)] // mirrors the documented runtime trait method for method
#[allow(clippy::missing_errors_doc)] // every Err is a deterministic kernel refusal
pub trait RefKernelHost {
    fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;
    fn locked_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;
    fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;
    fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), AbortReason>;
    fn delta_add(&mut self, rep: u32, amount: u128) -> Result<(), AbortReason>;
    fn delta_sub(&mut self, rep: u32, amount: u128) -> Result<(), AbortReason>;
    fn issuer_mint(&mut self, rep: u32, ids: &[u8]) -> Result<u32, AbortReason>;
    fn issuer_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason>;
    fn range_take(&mut self, rep: u32, ids: &[u8]) -> Result<u32, AbortReason>;
    fn range_put(&mut self, rep: u32, funds: u32, value: Vec<u8>) -> Result<(), AbortReason>;
    fn bucket_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;
    fn bucket_put(&mut self, rep: u32, other: u32) -> Result<(), AbortReason>;
    fn bucket_amount(&mut self, rep: u32) -> Result<u128, AbortReason>;
    fn delta_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason>;
    fn write_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason>;
    fn issuer_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;
    fn delta_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;
    fn write_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;
    fn reserve_amount(&mut self, rep: u32) -> Result<u128, AbortReason>;
    fn reserve_take(&mut self, rep: u32) -> Result<u32, AbortReason>;
    fn range_count(&mut self, rep: u32) -> Result<u32, AbortReason>;
    fn range_order(&mut self, rep: u32, index: u32) -> Result<u128, AbortReason>;
    fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, AbortReason>;
    fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), AbortReason>;
    fn range_insert(&mut self, rep: u32, order: u128, value: Vec<u8>) -> Result<(), AbortReason>;
    fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), AbortReason>;
    fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason>;
    /// The transaction clock in milliseconds.
    fn clock_ms(&self) -> u64;
    /// The transaction's randomness draw.
    fn randomness(&self) -> [u8; 32];
    /// The protocol hash function.
    fn hash(&self, data: &[u8]) -> [u8; 32];
    fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), AbortReason>;
}

/// The state interface's resource types: one per access mode, plus the
/// one that carries value.
///
/// Handles are typed with these, and lifting a borrow of the wrong type
/// traps exactly as the blessed engine's canonical ABI does — the
/// mode-escape trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// `bucket`: the world's only owned resource, and so the only one a
    /// guest can keep past a call or discard.
    Bucket,
    /// `issuer`: the authority to create value, granted per invocation.
    Issuer,
    /// `read-cell`.
    ReadCell,
    /// `locked-cell`.
    LockedCell,
    /// `write-cell`.
    WriteCell,
    /// `delta-cell`.
    DeltaCell,
    /// `reserve-cell`.
    ReserveCell,
    /// `range-read`.
    RangeRead,
    /// `range-write`.
    RangeWrite,
}

impl ResourceKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "bucket" => Some(Self::Bucket),
            "issuer" => Some(Self::Issuer),
            "read-cell" => Some(Self::ReadCell),
            "locked-cell" => Some(Self::LockedCell),
            "write-cell" => Some(Self::WriteCell),
            "delta-cell" => Some(Self::DeltaCell),
            "reserve-cell" => Some(Self::ReserveCell),
            "range-read" => Some(Self::RangeRead),
            "range-write" => Some(Self::RangeWrite),
            _ => None,
        }
    }
}

/// A component-level value at the export boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CVal {
    /// `u32`.
    U32(u32),
    /// `u64`.
    U64(u64),
    /// A borrowed capability handle carrying its host rep and its type.
    Borrow(u32, ResourceKind),
    /// An owned handle at its host rep.
    ///
    /// No type beside it, where a borrow carries one: the world owns a
    /// single resource, so what an `own` names is never in question. What
    /// crossing one means is ownership — the host's rep leaves its keeping
    /// on the way in and returns to it on the way out.
    Own(u32),
    /// An address, as the world's own four-word record.
    Address([u8; 32]),
    /// A `list<u8>` value at the export boundary.
    Bytes(Vec<u8>),
    /// A declined result: the code the guest returned on the error arm,
    /// an index into its package's error table.
    Declined(u32),
}

/// A kernel-world import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostFn {
    ReadCellGet,
    LockedCellGet,
    WriteCellGet,
    WriteCellSet,
    WriteTake,
    WritePut,
    IssuerMint,
    IssuerPut,
    RangeWriteTake,
    RangeWritePut,
    BucketTake,
    BucketPut,
    BucketAmount,
    IssuerTake,
    DeltaAdd,
    DeltaSub,
    DeltaTake,
    DeltaPut,
    ReserveAmount,
    ReserveTake,
    RangeReadCount,
    RangeReadOrder,
    RangeReadEntry,
    RangeWriteCount,
    RangeWriteOrder,
    RangeWriteEntry,
    RangeWriteSet,
    RangeWriteInsert,
    RangeWriteRemove,
    Clock,
    Randomness,
    Hash,
    Emit,
}

/// A component-level function.
#[derive(Debug, Clone, Copy)]
enum CompFunc {
    Host(HostFn),
    Lifted {
        core_func: u32,
        ty: u32,
        opts: CanonOpts,
        post_return: Option<u32>,
    },
}

/// A core-function definition.
#[derive(Debug, Clone)]
enum CoreFuncDef {
    Lower { func: u32, opts: CanonOpts },
    ResourceDrop { kind: Option<ResourceKind> },
    Alias { instance: u32, name: String },
}

#[derive(Debug, Clone, Copy, Default)]
struct CanonOpts {
    memory: Option<u32>,
    realloc: Option<u32>,
}

/// A core-instance definition.
#[derive(Debug)]
enum CoreInstanceDef {
    Instantiate {
        module: u32,
        args: Vec<(String, u32)>,
    },
    Exports(Vec<(String, ExternalKind, u32)>),
}

/// A component-level type entry. Resource entries track which state
/// resource an aliased or imported type names, so `resource.drop` can be
/// type-checked like the blessed engine does.
#[derive(Debug, Clone)]
enum CTypeEntry {
    Func(CType),
    Defined(CTy),
    Resource(ResourceKind),
    Other,
}

/// A component function type over the kernel world's value vocabulary.
#[derive(Debug, Clone)]
pub(crate) struct CType {
    params: Vec<CTy>,
    results: Vec<CTy>,
}

/// Where a `result`'s payload sits in its memory representation: one
/// discriminant byte, padded to the four-byte alignment both arms carry.
const RESULT_PAYLOAD: usize = 4;

/// What an amount costs at the boundary, and how wide it is in the return
/// area. The blessed engine charges the same figure.
const AMOUNT_BOUNDARY_BYTES: usize = 16;

/// A handle's width in a spilled result: the core `i32` it is.
const HANDLE_BYTES: usize = 4;

/// The amount a flattened `record { low: u64, high: u64 }` carries.
fn flat_amount(low: Value, high: Value) -> u128 {
    u128::from(low.as_i64().cast_unsigned()) | (u128::from(high.as_i64().cast_unsigned()) << 64)
}

/// A component value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CTy {
    U32,
    U64,
    List8,
    /// `record { u64, u64 }`: the kernel's own amount, flattened to its
    /// two halves as a parameter and written whole to the return area as
    /// a result.
    Amount,
    /// `record { u64, u64, u64, u64 }`: an address, flattened to its four
    /// words.
    Address,
    Borrow,
    /// `own<R>`: a handle the call transfers rather than lends.
    Own,
    /// `tuple<own<R>, …>`: how a method with more than one edge returns
    /// them, carrying the arity because that is what the lift walks.
    OwnTuple(u32),
    /// `result<_, u32>`: the refusal channel over a method that produces
    /// nothing.
    DeclinableUnit,
    /// The refusal channel over a method that produces edges, carrying
    /// how many. An error arm says how a method ends and nothing about
    /// what it produces, so the ok arm is the same shape it would have
    /// been without one.
    DeclinableOwn(u32),
}

/// A decoded component.
pub struct RefComponent {
    modules: Vec<RefModule>,
    types: Vec<CTypeEntry>,
    import_names: Vec<String>,
    comp_funcs: Vec<CompFunc>,
    core_funcs: Vec<CoreFuncDef>,
    core_memories: Vec<(u32, String)>,
    core_tables: Vec<(u32, String)>,
    core_instances: Vec<CoreInstanceDef>,
    exports: HashMap<String, u32>,
}

impl RefComponent {
    /// Decodes a component within the profile's contract shape.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for malformed binaries or structures outside the
    /// supported shape.
    #[allow(clippy::too_many_lines)] // one dispatch over component payloads
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut comp = Self {
            modules: Vec::new(),
            types: Vec::new(),
            import_names: Vec::new(),
            comp_funcs: Vec::new(),
            core_funcs: Vec::new(),
            core_memories: Vec::new(),
            core_tables: Vec::new(),
            core_instances: Vec::new(),
            exports: HashMap::new(),
        };
        for payload in Parser::new(0).parse_all(bytes) {
            let payload = payload.map_err(|e| DecodeError::Malformed(e.to_string()))?;
            match payload {
                Payload::ModuleSection {
                    unchecked_range, ..
                } => {
                    comp.modules
                        .push(RefModule::decode(&bytes[unchecked_range])?);
                }
                Payload::ComponentTypeSection(reader) => {
                    for entry in reader {
                        let entry = entry.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        comp.types.push(comp.parse_type(&entry)?);
                    }
                }
                Payload::ComponentImportSection(reader) => {
                    for import in reader {
                        let import = import.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        // Each import kind appends to its own index space:
                        // instances to the instance space, types (a
                        // world-level `use`) to the type space.
                        match import.ty {
                            ComponentTypeRef::Instance(_) => {
                                comp.import_names.push(import.name.name.to_string());
                            }
                            // A type import is either a `use` of a kernel
                            // resource, named as the interface exports
                            // it, or an equality import over a type the
                            // world declared — which is how a world's own
                            // value record reaches its exports' signatures.
                            ComponentTypeRef::Type(bound) => {
                                let entry = ResourceKind::from_name(import.name.name)
                                    .map(CTypeEntry::Resource)
                                    .or_else(|| match bound {
                                        TypeBounds::Eq(index) => {
                                            comp.types.get(index as usize).cloned()
                                        }
                                        TypeBounds::SubResource => None,
                                    })
                                    .unwrap_or(CTypeEntry::Other);
                                comp.types.push(entry);
                            }
                            other => {
                                return Err(DecodeError::Unsupported(format!(
                                    "component import {other:?}"
                                )));
                            }
                        }
                    }
                }
                Payload::ComponentAliasSection(reader) => {
                    for alias in reader {
                        let alias = alias.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        comp.record_alias(&alias)?;
                    }
                }
                Payload::ComponentCanonicalSection(reader) => {
                    for canon in reader {
                        let canon = canon.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        comp.record_canon(&canon)?;
                    }
                }
                Payload::InstanceSection(reader) => {
                    for instance in reader {
                        let instance =
                            instance.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        comp.record_core_instance(&instance)?;
                    }
                }
                Payload::ComponentExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        // An export also appends to the exported kind's
                        // index space; later definitions reference past it.
                        match export.kind {
                            ComponentExternalKind::Func => {
                                comp.exports
                                    .insert(export.name.name.to_string(), export.index);
                                let aliased = comp
                                    .comp_funcs
                                    .get(export.index as usize)
                                    .copied()
                                    .ok_or_else(|| {
                                    DecodeError::Malformed("export func index".to_string())
                                })?;
                                comp.comp_funcs.push(aliased);
                            }
                            ComponentExternalKind::Type => {
                                let aliased =
                                    comp.types.get(export.index as usize).cloned().ok_or_else(
                                        || DecodeError::Malformed("export type index".to_string()),
                                    )?;
                                comp.types.push(aliased);
                            }
                            _ => {}
                        }
                    }
                }
                Payload::ComponentSection { .. } => {
                    return Err(DecodeError::Unsupported("nested component".to_string()));
                }
                _ => {}
            }
        }
        Ok(comp)
    }

    fn parse_type(&self, entry: &ComponentType<'_>) -> Result<CTypeEntry, DecodeError> {
        Ok(match entry {
            ComponentType::Func(f) => {
                let mut params = Vec::new();
                for (_, vt) in &*f.params {
                    params.push(self.value_type(*vt)?);
                }
                let mut results = Vec::new();
                if let Some(vt) = f.result {
                    results.push(self.value_type(vt)?);
                }
                CTypeEntry::Func(CType { params, results })
            }
            ComponentType::Defined(d) => match d {
                ComponentDefinedType::List(ComponentValType::Primitive(PrimitiveValType::U8)) => {
                    CTypeEntry::Defined(CTy::List8)
                }
                ComponentDefinedType::List(_) => {
                    return Err(DecodeError::Unsupported("non-u8 list".to_string()));
                }
                // The profile admits a record whose fields are scalars,
                // and the kernel declares exactly one: two `u64` halves
                // of an amount. A record of any other shape is a type
                // this engine does not model rather than one it guesses
                // at.
                ComponentDefinedType::Record(fields) => {
                    let halves: Vec<CTy> = fields
                        .iter()
                        .map(|(_, vt)| self.value_type(*vt))
                        .collect::<Result<_, _>>()?;
                    match halves.as_slice() {
                        [CTy::U64, CTy::U64] => CTypeEntry::Defined(CTy::Amount),
                        [CTy::U64, CTy::U64, CTy::U64, CTy::U64] => {
                            CTypeEntry::Defined(CTy::Address)
                        }
                        _ => return Err(DecodeError::Unsupported("record shape".to_string())),
                    }
                }
                ComponentDefinedType::Borrow(_) => CTypeEntry::Defined(CTy::Borrow),
                ComponentDefinedType::Own(_) => CTypeEntry::Defined(CTy::Own),
                ComponentDefinedType::Tuple(elements) => {
                    for element in &**elements {
                        if self.value_type(*element)? != CTy::Own {
                            return Err(DecodeError::Unsupported("tuple element".to_string()));
                        }
                    }
                    CTypeEntry::Defined(CTy::OwnTuple(
                        u32::try_from(elements.len())
                            .map_err(|_| DecodeError::Unsupported("tuple arity".to_string()))?,
                    ))
                }
                // The profile pins the refusal channel to two shapes; a
                // component carrying anything else never reaches here,
                // and one that did would be a type this engine cannot
                // model rather than a decline it misreads.
                ComponentDefinedType::Result { ok, err } => {
                    if !matches!(
                        err,
                        Some(ComponentValType::Primitive(PrimitiveValType::U32))
                    ) {
                        return Err(DecodeError::Unsupported("result error arm".to_string()));
                    }
                    match ok.map(|vt| self.value_type(vt)).transpose()? {
                        None => CTypeEntry::Defined(CTy::DeclinableUnit),
                        Some(CTy::Own) => CTypeEntry::Defined(CTy::DeclinableOwn(1)),
                        Some(CTy::OwnTuple(arity)) => {
                            CTypeEntry::Defined(CTy::DeclinableOwn(arity))
                        }
                        Some(_) => {
                            return Err(DecodeError::Unsupported("result ok arm".to_string()));
                        }
                    }
                }
                _ => CTypeEntry::Other,
            },
            _ => CTypeEntry::Other,
        })
    }

    fn value_type(&self, vt: ComponentValType) -> Result<CTy, DecodeError> {
        match vt {
            ComponentValType::Primitive(PrimitiveValType::U32 | PrimitiveValType::U8) => {
                Ok(CTy::U32)
            }
            ComponentValType::Primitive(PrimitiveValType::U64) => Ok(CTy::U64),
            ComponentValType::Type(i) => match self.types.get(i as usize) {
                Some(CTypeEntry::Defined(t)) => Ok(*t),
                _ => Err(DecodeError::Unsupported("type reference".to_string())),
            },
            ComponentValType::Primitive(other) => {
                Err(DecodeError::Unsupported(format!("primitive {other:?}")))
            }
        }
    }

    fn record_alias(&mut self, alias: &ComponentAlias<'_>) -> Result<(), DecodeError> {
        match alias {
            ComponentAlias::InstanceExport {
                kind,
                instance_index,
                name,
            } => match kind {
                ComponentExternalKind::Func => {
                    let host = self.host_fn(*instance_index, name)?;
                    self.comp_funcs.push(CompFunc::Host(host));
                }
                ComponentExternalKind::Type => {
                    self.types.push(
                        ResourceKind::from_name(name)
                            .map_or(CTypeEntry::Other, CTypeEntry::Resource),
                    );
                }
                _ => {
                    return Err(DecodeError::Unsupported(format!(
                        "component alias kind {kind:?}"
                    )));
                }
            },
            ComponentAlias::CoreInstanceExport {
                kind,
                instance_index,
                name,
            } => match kind {
                ExternalKind::Func => self.core_funcs.push(CoreFuncDef::Alias {
                    instance: *instance_index,
                    name: (*name).to_string(),
                }),
                ExternalKind::Memory => {
                    self.core_memories
                        .push((*instance_index, (*name).to_string()));
                }
                ExternalKind::Table => {
                    self.core_tables
                        .push((*instance_index, (*name).to_string()));
                }
                _ => {
                    return Err(DecodeError::Unsupported(format!(
                        "core alias kind {kind:?}"
                    )));
                }
            },
            ComponentAlias::Outer { .. } => {
                return Err(DecodeError::Unsupported("outer alias".to_string()));
            }
        }
        Ok(())
    }

    fn host_fn(&self, instance: u32, name: &str) -> Result<HostFn, DecodeError> {
        let interface = self
            .import_names
            .get(instance as usize)
            .ok_or_else(|| DecodeError::Malformed("import index".to_string()))?;
        let suffix = interface
            .rsplit_once('/')
            .map_or(interface.as_str(), |(_, s)| s);
        match (suffix, name) {
            ("state", "read-cell-get") => Ok(HostFn::ReadCellGet),
            ("state", "locked-cell-get") => Ok(HostFn::LockedCellGet),
            ("state", "write-cell-get") => Ok(HostFn::WriteCellGet),
            ("state", "write-cell-set") => Ok(HostFn::WriteCellSet),
            ("state", "write-cell-take") => Ok(HostFn::WriteTake),
            ("state", "write-cell-put") => Ok(HostFn::WritePut),
            ("state", "issuer-mint") => Ok(HostFn::IssuerMint),
            ("state", "issuer-put") => Ok(HostFn::IssuerPut),
            ("state", "range-write-take") => Ok(HostFn::RangeWriteTake),
            ("state", "range-write-put") => Ok(HostFn::RangeWritePut),
            ("state", "bucket-take") => Ok(HostFn::BucketTake),
            ("state", "bucket-put") => Ok(HostFn::BucketPut),
            ("state", "bucket-amount") => Ok(HostFn::BucketAmount),
            ("state", "issuer-take") => Ok(HostFn::IssuerTake),
            ("state", "delta-cell-add") => Ok(HostFn::DeltaAdd),
            ("state", "delta-cell-sub") => Ok(HostFn::DeltaSub),
            ("state", "delta-cell-take") => Ok(HostFn::DeltaTake),
            ("state", "delta-cell-put") => Ok(HostFn::DeltaPut),
            ("state", "reserve-cell-amount") => Ok(HostFn::ReserveAmount),
            ("state", "reserve-cell-take") => Ok(HostFn::ReserveTake),
            ("state", "range-read-count") => Ok(HostFn::RangeReadCount),
            ("state", "range-read-order") => Ok(HostFn::RangeReadOrder),
            ("state", "range-read-entry") => Ok(HostFn::RangeReadEntry),
            ("state", "range-write-count") => Ok(HostFn::RangeWriteCount),
            ("state", "range-write-order") => Ok(HostFn::RangeWriteOrder),
            ("state", "range-write-entry") => Ok(HostFn::RangeWriteEntry),
            ("state", "range-write-set") => Ok(HostFn::RangeWriteSet),
            ("state", "range-write-insert") => Ok(HostFn::RangeWriteInsert),
            ("state", "range-write-remove") => Ok(HostFn::RangeWriteRemove),
            ("env", "clock") => Ok(HostFn::Clock),
            ("env", "randomness") => Ok(HostFn::Randomness),
            ("crypto", "hash") => Ok(HostFn::Hash),
            ("events", "emit") => Ok(HostFn::Emit),
            _ => Err(DecodeError::Unsupported(format!(
                "kernel import {interface}#{name}"
            ))),
        }
    }

    fn record_canon(&mut self, canon: &CanonicalFunction) -> Result<(), DecodeError> {
        match canon {
            CanonicalFunction::Lower {
                func_index,
                options,
            } => {
                let opts = parse_opts(options);
                self.core_funcs.push(CoreFuncDef::Lower {
                    func: *func_index,
                    opts,
                });
            }
            CanonicalFunction::ResourceDrop { resource } => {
                let kind = match self.types.get(*resource as usize) {
                    Some(CTypeEntry::Resource(kind)) => Some(*kind),
                    _ => None,
                };
                self.core_funcs.push(CoreFuncDef::ResourceDrop { kind });
            }
            CanonicalFunction::Lift {
                core_func_index,
                type_index,
                options,
            } => {
                let mut post_return = None;
                for option in options {
                    if let CanonicalOption::PostReturn(index) = option {
                        post_return = Some(*index);
                    }
                }
                self.comp_funcs.push(CompFunc::Lifted {
                    core_func: *core_func_index,
                    ty: *type_index,
                    opts: parse_opts(options),
                    post_return,
                });
            }
            other => {
                return Err(DecodeError::Unsupported(format!("canon {other:?}")));
            }
        }
        Ok(())
    }

    fn record_core_instance(
        &mut self,
        instance: &CoreInstanceReader<'_>,
    ) -> Result<(), DecodeError> {
        match instance {
            CoreInstanceReader::Instantiate { module_index, args } => {
                let mut arg_list = Vec::new();
                for arg in &**args {
                    if arg.kind != InstantiationArgKind::Instance {
                        return Err(DecodeError::Unsupported("non-instance arg".to_string()));
                    }
                    arg_list.push((arg.name.to_string(), arg.index));
                }
                self.core_instances.push(CoreInstanceDef::Instantiate {
                    module: *module_index,
                    args: arg_list,
                });
            }
            CoreInstanceReader::FromExports(exports) => {
                let mut list = Vec::new();
                for export in &**exports {
                    list.push((export.name.to_string(), export.kind, export.index));
                }
                self.core_instances.push(CoreInstanceDef::Exports(list));
            }
        }
        Ok(())
    }
}

fn parse_opts(options: &[CanonicalOption]) -> CanonOpts {
    let mut opts = CanonOpts::default();
    for opt in options {
        match opt {
            CanonicalOption::Memory(m) => opts.memory = Some(*m),
            CanonicalOption::Realloc(r) => opts.realloc = Some(*r),
            _ => {}
        }
    }
    opts
}

/// A resolved core-instance export.
#[derive(Clone, Copy)]
enum ResolvedItem {
    Func(FuncAddr),
    Memory(u32),
    Table(u32),
}

/// Resolves a core-function index to a callable address; alias entries look
/// up already-built instances.
fn resolve_core_func(
    comp: &RefComponent,
    instance_exports: &[HashMap<String, ResolvedItem>],
    index: u32,
) -> Result<FuncAddr, DecodeError> {
    match comp
        .core_funcs
        .get(index as usize)
        .ok_or_else(|| DecodeError::Malformed("core func index".to_string()))?
    {
        CoreFuncDef::Lower { .. } | CoreFuncDef::ResourceDrop { .. } => Ok(FuncAddr::Canon(index)),
        CoreFuncDef::Alias { instance, name } => instance_exports
            .get(*instance as usize)
            .and_then(|m| m.get(name))
            .and_then(|item| match item {
                ResolvedItem::Func(addr) => Some(*addr),
                _ => None,
            })
            .ok_or_else(|| DecodeError::Malformed("core func alias".to_string())),
    }
}

/// Resolves an aliased core memory or table through its exporting instance.
fn resolve_alias<T>(
    aliases: &[(u32, String)],
    instance_exports: &[HashMap<String, ResolvedItem>],
    index: u32,
    pick: impl Fn(ResolvedItem) -> Option<T>,
) -> Result<T, DecodeError> {
    let (instance, name) = aliases
        .get(index as usize)
        .ok_or_else(|| DecodeError::Malformed("alias index".to_string()))?;
    instance_exports
        .get(*instance as usize)
        .and_then(|m| m.get(name))
        .and_then(|item| pick(*item))
        .ok_or_else(|| DecodeError::Malformed("alias resolution".to_string()))
}

/// A live handle-table entry, typed with its resource kind.
struct Handle {
    rep: u32,
    kind: ResourceKind,
    live: bool,
    /// Whether the guest owns the handle or was lent it.
    ///
    /// It decides two things a borrow and an own differ on: an own
    /// outlives the call that delivered it, so it is not what the
    /// end-of-call borrow check looks at; and dropping one reaches the
    /// host, where dropping a borrow only returns the lender's slot.
    own: bool,
}

/// The handle table's reserved slot.
///
/// The component model reserves index 0 as never allocatable, so the
/// blessed engine's table numbers from one (`HandleTable::insert` returns
/// `next + 1`). Handle values are core `i32`s a guest can return, compare,
/// or forge, so the numbering is guest-observable and has to match.
const RESERVED_HANDLE: Option<Handle> = None;

/// The canonical-ABI runtime: handle table plus the host, implementing canon
/// dispatch for the interpreter.
struct KernelCanon<'c, H> {
    comp: &'c RefComponent,
    resolved_core_funcs: Vec<FuncAddr>,
    resolved_memories: Vec<u32>,
    handles: Vec<Option<Handle>>,
    /// Freed handle slots, reused most recent first. The table lives as
    /// long as the instance and its numbering is guest-observable, so
    /// both the persistence and the reuse order have to match the blessed
    /// engine's table exactly.
    free: Vec<u32>,
    /// Bytes crossing the canonical ABI boundary, mirroring the runtime's
    /// per-byte fuel supplement.
    boundary_bytes: u64,
    /// Whether guest code may currently leave the component instance.
    ///
    /// The canonical ABI runs two pieces of guest code as its own
    /// callbacks — `realloc`, while it lowers a value, and `post-return`,
    /// after it has lifted one — and neither may call a lowered import: the
    /// lowering it would interrupt is mid-flight, and the instance is not
    /// in a state to be re-entered on the way back. Guest code reached any
    /// other way leaves freely. Without this rule a call cycle can close
    /// through the boundary — realloc calling an import whose lowering
    /// calls realloc — with every edge sound and the recursion unbounded.
    may_leave: bool,
    host: H,
}

/// Fuel charged per boundary byte; must equal the runtime's rate (asserted by
/// the differential fuel lane).
pub const FUEL_PER_BOUNDARY_BYTE: u64 = 1;

/// An instantiated component.
pub struct RefComponentInstance<'c, H> {
    comp: &'c RefComponent,
    store: Store,
    canon: KernelCanon<'c, H>,
}

impl<'c, H: RefKernelHost> RefComponentInstance<'c, H> {
    /// Instantiates the component against a host.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for unresolvable structure, or a trap at core
    /// instantiation from an out-of-bounds active segment — with the
    /// host handed back, since an embedder's session must survive a
    /// refused instantiation.
    ///
    /// # Panics
    ///
    /// Only on index-space overflow past `u32`, which the profile's
    /// structural limits exclude.
    pub fn instantiate(comp: &'c RefComponent, host: H) -> Result<Self, (H, DecodeError)> {
        let (store, resolved_core_funcs, resolved_memories) = match Self::resolve(comp) {
            Ok(parts) => parts,
            Err(error) => return Err((host, error)),
        };
        Ok(Self {
            comp,
            store,
            canon: KernelCanon {
                comp,
                resolved_core_funcs,
                resolved_memories,
                handles: vec![RESERVED_HANDLE],
                free: Vec::new(),
                boundary_bytes: 0,
                may_leave: true,
                host,
            },
        })
    }

    /// The host-free half of instantiation: core instances built, index
    /// spaces resolved, active segments applied.
    #[allow(clippy::too_many_lines)] // the instantiation walk is one pass over defs
    fn resolve(comp: &'c RefComponent) -> Result<(Store, Vec<FuncAddr>, Vec<u32>), DecodeError> {
        let modules: Vec<&RefModule> = comp.modules.iter().collect();
        let mut store = Store::default();
        // Core instance index -> resolved export map.
        let mut instance_exports: Vec<HashMap<String, ResolvedItem>> = Vec::new();

        for def in &comp.core_instances {
            match def {
                CoreInstanceDef::Exports(list) => {
                    let mut map = HashMap::new();
                    for (name, kind, index) in list {
                        let resolved = match kind {
                            ExternalKind::Func => ResolvedItem::Func(resolve_core_func(
                                comp,
                                &instance_exports,
                                *index,
                            )?),
                            ExternalKind::Memory => ResolvedItem::Memory(resolve_alias(
                                &comp.core_memories,
                                &instance_exports,
                                *index,
                                |item| match item {
                                    ResolvedItem::Memory(m) => Some(m),
                                    _ => None,
                                },
                            )?),
                            ExternalKind::Table => ResolvedItem::Table(resolve_alias(
                                &comp.core_tables,
                                &instance_exports,
                                *index,
                                |item| match item {
                                    ResolvedItem::Table(t) => Some(t),
                                    _ => None,
                                },
                            )?),
                            _ => {
                                return Err(DecodeError::Unsupported(
                                    "export instance kind".to_string(),
                                ));
                            }
                        };
                        map.insert(name.clone(), resolved);
                    }
                    instance_exports.push(map);
                }
                CoreInstanceDef::Instantiate { module, args } => {
                    let m = comp
                        .modules
                        .get(*module as usize)
                        .ok_or_else(|| DecodeError::Malformed("module index".to_string()))?;
                    let mut imported_funcs = Vec::new();
                    let mut imported_memory = None;
                    let mut imported_table = None;
                    for import in &m.imports.entries {
                        let (_, arg_instance) = args
                            .iter()
                            .find(|(n, _)| *n == import.module)
                            .ok_or_else(|| {
                                DecodeError::Malformed(format!("missing arg {}", import.module))
                            })?;
                        let exports = instance_exports
                            .get(*arg_instance as usize)
                            .ok_or_else(|| DecodeError::Malformed("arg instance".to_string()))?;
                        let item = exports.get(&import.name).ok_or_else(|| {
                            DecodeError::Malformed(format!("missing export {}", import.name))
                        })?;
                        match (import.kind, item) {
                            (CoreImportKind::Func(_), ResolvedItem::Func(addr)) => {
                                imported_funcs.push(*addr);
                            }
                            (CoreImportKind::Memory, ResolvedItem::Memory(mem)) => {
                                imported_memory = Some(*mem);
                            }
                            (CoreImportKind::Table, ResolvedItem::Table(table)) => {
                                imported_table = Some(*table);
                            }
                            _ => {
                                return Err(DecodeError::Malformed(
                                    "import kind mismatch".to_string(),
                                ));
                            }
                        }
                    }
                    let instance_idx = instantiate_module(
                        &modules,
                        &mut store,
                        *module,
                        imported_funcs,
                        imported_memory,
                        imported_table,
                    )
                    .map_err(|t| DecodeError::Malformed(format!("instantiation trap: {t}")))?;
                    // Expose this instance's exports for later definitions.
                    let mut map = HashMap::new();
                    for (name, func_idx) in &m.exports {
                        map.insert(
                            name.clone(),
                            ResolvedItem::Func(
                                store.instances[instance_idx as usize].funcs[*func_idx as usize],
                            ),
                        );
                    }
                    if let Some(mem) = store.instances[instance_idx as usize].memory {
                        for name in &m.memory_exports {
                            map.insert(name.clone(), ResolvedItem::Memory(mem));
                        }
                    }
                    if let Some(table) = store.instances[instance_idx as usize].table {
                        for name in &m.table_exports {
                            map.insert(name.clone(), ResolvedItem::Table(table));
                        }
                    }
                    instance_exports.push(map);
                }
            }
        }

        // Resolve the core-function and core-memory index spaces.
        let mut resolved_core_funcs = Vec::new();
        for i in 0..comp.core_funcs.len() {
            resolved_core_funcs.push(resolve_core_func(
                comp,
                &instance_exports,
                u32::try_from(i).expect("bounded"),
            )?);
        }
        let mut resolved_memories_by_alias: Vec<u32> = Vec::new();
        for i in 0..comp.core_memories.len() {
            resolved_memories_by_alias.push(resolve_alias(
                &comp.core_memories,
                &instance_exports,
                u32::try_from(i).expect("bounded"),
                |item| match item {
                    ResolvedItem::Memory(m) => Some(m),
                    _ => None,
                },
            )?);
        }

        Ok((store, resolved_core_funcs, resolved_memories_by_alias))
    }

    /// Invokes a component export.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for bad invocations; [`ExecError`] for traps and
    /// canonical-ABI violations.
    ///
    /// # Panics
    ///
    /// Only on index-space overflow past `u32`, which the profile's
    /// structural limits exclude.
    #[allow(clippy::too_many_lines)] // one pass: lower args, call, lift results
    pub fn invoke(
        &mut self,
        export: &str,
        args: &[CVal],
    ) -> Result<Result<Vec<CVal>, ExecError>, DecodeError> {
        let func_idx = *self
            .comp
            .exports
            .get(export)
            .ok_or_else(|| DecodeError::NoSuchExport(export.to_string()))?;
        let CompFunc::Lifted {
            core_func,
            ty,
            opts,
            post_return,
        } = self.comp.comp_funcs[func_idx as usize]
        else {
            return Err(DecodeError::Unsupported("export of an import".to_string()));
        };
        let CTypeEntry::Func(ctype) = self.comp.types[ty as usize].clone() else {
            return Err(DecodeError::Malformed("lift type".to_string()));
        };
        if ctype.params.len() != args.len() {
            return Err(DecodeError::ArgumentMismatch);
        }

        let modules: Vec<&RefModule> = self.comp.modules.iter().collect();
        self.store.depth = 0;
        self.canon.may_leave = true;
        let mem_idx = opts
            .memory
            .and_then(|m| self.canon.resolved_memories.get(m as usize).copied());
        let realloc = opts
            .realloc
            .and_then(|r| self.canon.resolved_core_funcs.get(r as usize).copied());

        let mut flat = Vec::new();
        for (arg, want) in args.iter().zip(&ctype.params) {
            match (arg, want) {
                (CVal::U32(v), CTy::U32) => flat.push(Value::I32(v.cast_signed())),
                (CVal::U64(v), CTy::U64) => flat.push(Value::I64(v.cast_signed())),
                (CVal::Borrow(rep, kind), CTy::Borrow) => {
                    let idx = self.canon.insert(Handle {
                        rep: *rep,
                        kind: *kind,
                        live: true,
                        own: false,
                    });
                    flat.push(Value::I32(idx.cast_signed()));
                }
                (CVal::Own(rep), CTy::Own) => {
                    let idx = self.canon.insert(Handle {
                        rep: *rep,
                        kind: ResourceKind::Bucket,
                        live: true,
                        own: true,
                    });
                    flat.push(Value::I32(idx.cast_signed()));
                }
                (CVal::Address(bytes), CTy::Address) => {
                    // Four words, flattened: a record of scalars crosses
                    // in the flat arguments and touches no memory.
                    for word in bytes.as_chunks::<8>().0 {
                        flat.push(Value::I64(u64::from_le_bytes(*word).cast_signed()));
                    }
                }
                (CVal::Bytes(bytes), CTy::List8) => {
                    // Lower through the lift options: the guest's realloc
                    // allocates, the bytes copy in, the (ptr, len) pair
                    // joins the flat arguments — exactly the blessed
                    // engine's argument path, realloc metered as guest
                    // code on both.
                    let (Some(mem), Some(realloc)) = (mem_idx, realloc) else {
                        return Err(DecodeError::Unsupported(
                            "list argument without lift options".to_string(),
                        ));
                    };
                    let len =
                        i32::try_from(bytes.len()).map_err(|_| DecodeError::ArgumentMismatch)?;
                    self.canon.may_leave = false;
                    let allocated = call(
                        &modules,
                        &mut self.canon,
                        &mut self.store,
                        realloc,
                        vec![Value::I32(0), Value::I32(0), Value::I32(1), Value::I32(len)],
                    );
                    self.canon.may_leave = true;
                    let ptr = match allocated {
                        Ok(values) => values.first().copied().unwrap_or(Value::I32(0)).as_i32(),
                        Err(e) => return Ok(Err(e)),
                    };
                    let memory = &mut self.store.memories[mem as usize];
                    let start = usize::try_from(ptr.cast_unsigned()).expect("32-bit");
                    let Some(end) = start.checked_add(bytes.len()) else {
                        return Ok(Err(ExecError::Trap(Trap::MemoryOutOfBounds)));
                    };
                    if end > memory.data.len() {
                        return Ok(Err(ExecError::Trap(Trap::MemoryOutOfBounds)));
                    }
                    memory.data[start..end].copy_from_slice(bytes);
                    flat.push(Value::I32(ptr));
                    flat.push(Value::I32(len));
                }
                _ => return Err(DecodeError::ArgumentMismatch),
            }
        }

        let addr = self.canon.resolved_core_funcs[core_func as usize];
        let outcome = call(&modules, &mut self.canon, &mut self.store, addr, flat);
        let result = match outcome {
            Ok(values) => {
                // Borrows only: what a call lends it takes back at scope
                // exit, where an owned handle is the guest's to keep for
                // as long as the instance lives.
                if self
                    .canon
                    .handles
                    .iter()
                    .flatten()
                    .any(|h| h.live && !h.own)
                {
                    Err(ExecError::Canon(CanonError::BorrowsRemain))
                } else {
                    let lifted = self.lift_results(&ctype, &values, mem_idx);
                    if let Ok(_) = &lifted
                        && let Some(index) = post_return
                        && let Some(addr) =
                            self.canon.resolved_core_funcs.get(index as usize).copied()
                    {
                        let modules: Vec<&RefModule> = self.comp.modules.iter().collect();
                        self.canon.may_leave = false;
                        let returned =
                            call(&modules, &mut self.canon, &mut self.store, addr, values);
                        self.canon.may_leave = true;
                        if let Err(e) = returned {
                            return Ok(Err(e));
                        }
                    }
                    lifted
                }
            }
            Err(e) => Err(e),
        };
        Ok(result)
    }

    /// Lift the core return values per the export's declared results:
    /// scalars come back flat; anything wider spills to a return area the
    /// single returned pointer names.
    fn lift_results(
        &mut self,
        ctype: &CType,
        values: &[Value],
        mem_idx: Option<u32>,
    ) -> Result<Vec<CVal>, ExecError> {
        let area = || values.first().map_or(0, |v| v.as_i32().cast_unsigned()) as usize;
        match ctype.results.as_slice() {
            [] => Ok(Vec::new()),
            [CTy::Own] => Ok(vec![CVal::Own(self.lift_own(area())?)]),
            // One own per element, flattened into the result list: a
            // tuple of handles is what a method's edges are, and nothing
            // downstream wants them re-wrapped. One element fits the flat
            // limit and arrives as the handle itself; anything wider
            // spills, and the elements sit at their own alignment in the
            // area the single returned pointer names.
            [CTy::OwnTuple(arity)] => {
                let mut owned = Vec::with_capacity(*arity as usize);
                if *arity == 1 {
                    owned.push(CVal::Own(self.lift_own(area())?));
                } else {
                    for index in 0..*arity {
                        let at = area() + (index as usize) * HANDLE_BYTES;
                        let handle = self.lift_u32(mem_idx, at)? as usize;
                        owned.push(CVal::Own(self.lift_own(handle)?));
                    }
                }
                Ok(owned)
            }
            [CTy::U32] => Ok(vec![CVal::U32(
                values.first().map_or(0, |v| v.as_i32().cast_unsigned()),
            )]),
            [CTy::U64] => Ok(vec![CVal::U64(
                values.first().map_or(0, |v| v.as_i64().cast_unsigned()),
            )]),
            [CTy::List8] => Ok(vec![CVal::Bytes(self.lift_list(mem_idx, area())?)]),
            // The refusal channel spills like any result the canonical
            // ABI cannot flatten: a one-byte discriminant, then the
            // arm's payload at the offset the wider arm's alignment
            // fixes. Both shapes share that layout and differ only in
            // what the ok arm carries.
            [CTy::DeclinableUnit] => {
                if self.discriminant(mem_idx, area())? == 0 {
                    Ok(Vec::new())
                } else {
                    Ok(vec![CVal::Declined(
                        self.lift_u32(mem_idx, area() + RESULT_PAYLOAD)?,
                    )])
                }
            }
            [CTy::DeclinableOwn(arity)] => {
                if self.discriminant(mem_idx, area())? != 0 {
                    return Ok(vec![CVal::Declined(
                        self.lift_u32(mem_idx, area() + RESULT_PAYLOAD)?,
                    )]);
                }
                let mut owned = Vec::with_capacity(*arity as usize);
                for index in 0..*arity {
                    let at = area() + RESULT_PAYLOAD + (index as usize) * HANDLE_BYTES;
                    let handle = self.lift_u32(mem_idx, at)? as usize;
                    owned.push(CVal::Own(self.lift_own(handle)?));
                }
                Ok(owned)
            }
            _ => Err(ExecError::Canon(CanonError::Internal("result shape"))),
        }
    }

    /// Lifts an owned handle out of the table: the guest gives up the
    /// slot, the host has the rep back, and the slot rejoins the free
    /// list — which is why a later call can be lowered into it.
    fn lift_own(&mut self, idx: usize) -> Result<u32, ExecError> {
        match self.canon.handles.get(idx) {
            Some(Some(h)) if h.live && h.own => {
                let rep = h.rep;
                self.canon.free_slot(idx);
                Ok(rep)
            }
            Some(Some(h)) if h.live => Err(ExecError::Canon(CanonError::WrongHandleType)),
            _ => Err(ExecError::Canon(CanonError::UnknownHandle)),
        }
    }

    /// The bytes of a `list<u8>` whose `(ptr, len)` pair sits at `at`.
    fn lift_list(&self, mem_idx: Option<u32>, at: usize) -> Result<Vec<u8>, ExecError> {
        let memory = self.lifting_memory(mem_idx)?;
        let ptr = self.lift_u32(mem_idx, at)? as usize;
        let len = self.lift_u32(mem_idx, at + 4)? as usize;
        let Some(end) = ptr.checked_add(len) else {
            return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
        };
        if end > memory.data.len() {
            return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
        }
        Ok(memory.data[ptr..end].to_vec())
    }

    /// The `u32` at `at`.
    fn lift_u32(&self, mem_idx: Option<u32>, at: usize) -> Result<u32, ExecError> {
        let memory = self.lifting_memory(mem_idx)?;
        let Some(end) = at.checked_add(4) else {
            return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
        };
        if end > memory.data.len() {
            return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
        }
        Ok(u32::from_le_bytes(
            memory.data[at..end].try_into().expect("4 bytes"),
        ))
    }

    /// The one-byte variant discriminant at `at`.
    fn discriminant(&self, mem_idx: Option<u32>, at: usize) -> Result<u8, ExecError> {
        let memory = self.lifting_memory(mem_idx)?;
        memory
            .data
            .get(at)
            .copied()
            .ok_or(ExecError::Trap(Trap::MemoryOutOfBounds))
    }

    /// The memory the lift options name, or the defect of naming none
    /// while returning something that needs one.
    fn lifting_memory(&self, mem_idx: Option<u32>) -> Result<&Memory, ExecError> {
        let index = mem_idx.ok_or(ExecError::Canon(CanonError::Internal(
            "spilled result without a memory option",
        )))? as usize;
        self.store
            .memories
            .get(index)
            .ok_or(ExecError::Canon(CanonError::Internal("memory option")))
    }

    /// Bounds execution to `limit` fuel: the instruction schedule plus the
    /// boundary supplement, the same total the runtime meters.
    pub const fn set_fuel_limit(&mut self, limit: u64) {
        self.store.fuel_limit = Some(limit);
    }

    /// Total fuel consumed: the spec instruction schedule plus the boundary
    /// byte supplement, matching the blessed runtime's accounting.
    #[must_use]
    pub const fn fuel_consumed(&self) -> u64 {
        self.store.fuel_consumed + self.canon.boundary_bytes * FUEL_PER_BOUNDARY_BYTE
    }

    /// Consumes the instance, returning the host.
    pub fn into_host(self) -> H {
        self.canon.host
    }
}

impl<H: RefKernelHost> KernelCanon<'_, H> {
    fn canon_opts(&self, id: u32) -> Result<CanonOpts, ExecError> {
        match &self.comp.core_funcs[id as usize] {
            CoreFuncDef::Lower { opts, .. } => Ok(*opts),
            _ => Err(ExecError::Canon(CanonError::Internal("opts on non-lower"))),
        }
    }

    /// The lower's memory option, resolved to a store memory index.
    fn mem_opt(&self, id: u32) -> Result<u32, ExecError> {
        self.canon_opts(id)?
            .memory
            .and_then(|m| self.resolved_memories.get(m as usize).copied())
            .ok_or(ExecError::Canon(CanonError::Internal("memory option")))
    }

    /// The lower's realloc option, resolved to a callable address.
    fn realloc_opt(&self, id: u32) -> Result<FuncAddr, ExecError> {
        self.canon_opts(id)?
            .realloc
            .and_then(|r| self.resolved_core_funcs.get(r as usize).copied())
            .ok_or(ExecError::Canon(CanonError::Internal("realloc option")))
    }

    /// Charges the canonical-ABI boundary supplement against the same
    /// budget the instruction schedule draws on, mirroring the runtime's
    /// `charge_boundary_bytes`: argument bytes before the host operation,
    /// result bytes after it succeeds.
    const fn charge_boundary(&mut self, store: &Store, bytes: usize) -> Result<(), ExecError> {
        self.boundary_bytes += bytes as u64;
        let total = store
            .fuel_consumed
            .saturating_add(self.boundary_bytes * FUEL_PER_BOUNDARY_BYTE);
        match store.fuel_limit {
            Some(limit) if total > limit => Err(ExecError::Trap(Trap::OutOfFuel)),
            _ => Ok(()),
        }
    }

    /// Seats a handle, reusing the most recently freed slot.
    ///
    /// The numbering is guest-observable — a handle value is a core `i32`
    /// a body can return or compare — so both the reuse order and the
    /// table's persistence across calls have to match the blessed
    /// engine's exactly.
    ///
    /// # Panics
    ///
    /// Only on index-space overflow past `u32`.
    fn insert(&mut self, handle: Handle) -> u32 {
        if let Some(slot) = self.free.pop() {
            self.handles[slot as usize] = Some(handle);
            slot
        } else {
            let idx = u32::try_from(self.handles.len()).expect("bounded");
            self.handles.push(Some(handle));
            idx
        }
    }

    /// Seats a bucket the host just opened as an owned handle.
    fn seat_bucket(&mut self, rep: u32) -> u32 {
        self.insert(Handle {
            rep,
            kind: ResourceKind::Bucket,
            live: true,
            own: true,
        })
    }

    /// Lifts an owned handle passed as an import argument: the guest
    /// gives up the slot and the host has the rep.
    ///
    /// The mirror of seating one, and the reason a put cannot be undone
    /// by a body — what it hands over stops being nameable.
    fn consume_bucket(&mut self, index: Value) -> Result<u32, ExecError> {
        let idx = index.as_i32().cast_unsigned() as usize;
        match self.handles.get(idx) {
            Some(Some(h)) if h.live && h.own => {
                let rep = h.rep;
                self.free_slot(idx);
                Ok(rep)
            }
            Some(Some(h)) if h.live => Err(ExecError::Canon(CanonError::WrongHandleType)),
            _ => Err(ExecError::Canon(CanonError::UnknownHandle)),
        }
    }

    /// Empties the slot at `idx`, returning it for reuse.
    ///
    /// # Panics
    ///
    /// Only on index-space overflow past `u32`.
    fn free_slot(&mut self, idx: usize) {
        self.handles[idx] = None;
        self.free.push(u32::try_from(idx).expect("bounded"));
    }

    fn resolve_handle(&self, index: Value, expected: ResourceKind) -> Result<u32, ExecError> {
        let idx = index.as_i32().cast_unsigned() as usize;
        match self.handles.get(idx) {
            Some(Some(h)) if h.live && h.kind == expected => Ok(h.rep),
            Some(Some(h)) if h.live => Err(ExecError::Canon(CanonError::WrongHandleType)),
            _ => Err(ExecError::Canon(CanonError::UnknownHandle)),
        }
    }

    /// Lowers `bytes` into guest memory via realloc and writes the (ptr, len)
    /// pair at `retptr`.
    fn lower_list(
        &mut self,
        modules: &[&RefModule],
        store: &mut Store,
        mem_idx: u32,
        realloc: FuncAddr,
        bytes: &[u8],
        retptr: Value,
    ) -> Result<(), ExecError> {
        let len =
            i32::try_from(bytes.len()).map_err(|_| ExecError::Trap(Trap::MemoryOutOfBounds))?;
        let outer = std::mem::replace(&mut self.may_leave, false);
        let results = call(
            modules,
            self,
            store,
            realloc,
            vec![Value::I32(0), Value::I32(0), Value::I32(1), Value::I32(len)],
        );
        self.may_leave = outer;
        let results = results?;
        let ptr = results.first().copied().unwrap_or(Value::I32(0)).as_i32();
        let mem = &mut store.memories[mem_idx as usize];
        let start = usize::try_from(ptr.cast_unsigned()).expect("32-bit");
        let end = start
            .checked_add(bytes.len())
            .ok_or(ExecError::Trap(Trap::MemoryOutOfBounds))?;
        if end > mem.data.len() {
            return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
        }
        mem.data[start..end].copy_from_slice(bytes);
        let ret = usize::try_from(retptr.as_i32().cast_unsigned()).expect("32-bit");
        if ret + 8 > mem.data.len() {
            return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
        }
        mem.data[ret..ret + 4].copy_from_slice(&ptr.to_le_bytes());
        mem.data[ret + 4..ret + 8].copy_from_slice(&len.to_le_bytes());
        Ok(())
    }

    /// Writes an amount whole into the guest's return area.
    ///
    /// Two `u64`s wide, and no realloc: a flat record's result travels in
    /// the area the caller already reserved, where a list travels in a
    /// buffer the guest has to be asked to allocate.
    fn write_amount(
        store: &mut Store,
        mem_idx: u32,
        retptr: Value,
        amount: u128,
    ) -> Result<(), ExecError> {
        let mem = &mut store.memories[mem_idx as usize];
        let at = usize::try_from(retptr.as_i32().cast_unsigned()).expect("32-bit");
        let end = at
            .checked_add(AMOUNT_BOUNDARY_BYTES)
            .ok_or(ExecError::Trap(Trap::MemoryOutOfBounds))?;
        if end > mem.data.len() {
            return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
        }
        mem.data[at..end].copy_from_slice(&amount.to_le_bytes());
        Ok(())
    }

    fn read_guest_bytes(
        store: &Store,
        mem_idx: u32,
        ptr: Value,
        len: Value,
    ) -> Result<Vec<u8>, ExecError> {
        let mem = &store.memories[mem_idx as usize];
        let start = usize::try_from(ptr.as_i32().cast_unsigned()).expect("32-bit");
        let n = usize::try_from(len.as_i32().cast_unsigned()).expect("32-bit");
        let end = start
            .checked_add(n)
            .ok_or(ExecError::Trap(Trap::MemoryOutOfBounds))?;
        if end > mem.data.len() {
            return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
        }
        Ok(mem.data[start..end].to_vec())
    }
}

impl<H: RefKernelHost> CanonDispatch for KernelCanon<'_, H> {
    fn param_count(&self, id: u32) -> usize {
        match &self.comp.core_funcs[id as usize] {
            CoreFuncDef::ResourceDrop { .. } => 1,
            CoreFuncDef::Lower { func, .. } => match self.comp.comp_funcs[*func as usize] {
                // A take's bucket comes back as a flat handle, so it
                // costs no return-area pointer where the read beside it
                // needs one for the amount — which is why each take
                // counts one lower than the read it stands next to.
                CompFunc::Host(
                    HostFn::RangeReadCount
                    | HostFn::RangeWriteCount
                    | HostFn::Randomness
                    | HostFn::ReserveTake,
                ) => 1,
                CompFunc::Host(
                    HostFn::ReadCellGet
                    | HostFn::LockedCellGet
                    | HostFn::WriteCellGet
                    | HostFn::ReserveAmount
                    | HostFn::RangeWriteRemove
                    | HostFn::WritePut
                    | HostFn::DeltaPut
                    | HostFn::BucketAmount
                    | HostFn::BucketPut
                    | HostFn::IssuerPut,
                ) => 2,
                CompFunc::Host(
                    HostFn::WriteCellSet
                    | HostFn::WriteTake
                    | HostFn::IssuerTake
                    | HostFn::BucketTake
                    | HostFn::DeltaAdd
                    | HostFn::DeltaSub
                    | HostFn::DeltaTake
                    | HostFn::RangeReadOrder
                    | HostFn::RangeReadEntry
                    | HostFn::RangeWriteOrder
                    | HostFn::RangeWriteEntry
                    | HostFn::Hash
                    | HostFn::Emit
                    | HostFn::RangeWriteTake
                    | HostFn::IssuerMint,
                ) => 3,
                CompFunc::Host(HostFn::RangeWritePut | HostFn::RangeWriteSet) => 4,

                CompFunc::Host(HostFn::RangeWriteInsert) => 5,
                CompFunc::Host(HostFn::Clock) | CompFunc::Lifted { .. } => 0,
            },
            CoreFuncDef::Alias { .. } => unreachable!("aliases resolve to wasm addresses"),
        }
    }

    #[allow(clippy::too_many_lines)] // one dispatch over the world's host functions
    fn dispatch(
        &mut self,
        modules: &[&RefModule],
        store: &mut Store,
        id: u32,
        args: Vec<Value>,
    ) -> Result<Vec<Value>, ExecError> {
        // Every canon builtin dispatched here leaves the instance —
        // `resource.drop` no less than a lowered import — so the may-leave
        // rule is checked for the set, not per arm.
        if !self.may_leave {
            return Err(ExecError::Canon(CanonError::CannotLeave));
        }
        let def = self.comp.core_funcs[id as usize].clone();
        match def {
            CoreFuncDef::ResourceDrop { kind } => {
                let idx = args[0].as_i32().cast_unsigned() as usize;
                match self.handles.get(idx) {
                    Some(Some(h)) if h.live && kind.is_none_or(|k| k == h.kind) => {
                        // Dropping an owned handle destroys the resource,
                        // so it reaches the host's own destructor; a
                        // borrow's drop only hands the lender's slot
                        // back. That difference is the whole of what
                        // ownership buys, and it is the host that
                        // decides what a discarded bucket means.
                        let (rep, own) = (h.rep, h.own);
                        self.free_slot(idx);
                        if own {
                            self.host
                                .bucket_drop(rep)
                                .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        }
                        Ok(Vec::new())
                    }
                    Some(Some(h)) if h.live => Err(ExecError::Canon(CanonError::WrongHandleType)),
                    _ => Err(ExecError::Canon(CanonError::UnknownHandle)),
                }
            }
            CoreFuncDef::Lower { func, .. } => {
                let CompFunc::Host(host_fn) = self.comp.comp_funcs[func as usize] else {
                    return Err(ExecError::Canon(CanonError::Internal(
                        "lower of non-import",
                    )));
                };
                match host_fn {
                    HostFn::Clock => Ok(vec![Value::I64(self.host.clock_ms().cast_signed())]),
                    HostFn::ReadCellGet | HostFn::LockedCellGet | HostFn::WriteCellGet => {
                        let expected = match host_fn {
                            HostFn::ReadCellGet => ResourceKind::ReadCell,
                            HostFn::LockedCellGet => ResourceKind::LockedCell,
                            _ => ResourceKind::WriteCell,
                        };
                        let rep = self.resolve_handle(args[0], expected)?;
                        let result = match host_fn {
                            HostFn::ReadCellGet => self.host.read_cell(rep),
                            HostFn::LockedCellGet => self.host.locked_cell(rep),
                            _ => self.host.write_cell_get(rep),
                        };
                        let bytes = result.map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        self.charge_boundary(store, bytes.len())?;
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        self.lower_list(modules, store, mem, realloc, &bytes, args[1])?;
                        Ok(Vec::new())
                    }
                    HostFn::ReserveAmount => {
                        let rep = self.resolve_handle(args[0], ResourceKind::ReserveCell)?;
                        let amount = self
                            .host
                            .reserve_amount(rep)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        self.charge_boundary(store, AMOUNT_BOUNDARY_BYTES)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_amount(store, mem, args[1], amount)?;
                        Ok(Vec::new())
                    }
                    HostFn::WriteCellSet => {
                        let rep = self.resolve_handle(args[0], ResourceKind::WriteCell)?;
                        let mem = self.mem_opt(id)?;
                        let bytes = Self::read_guest_bytes(store, mem, args[1], args[2])?;
                        self.charge_boundary(store, bytes.len())?;
                        self.host
                            .write_cell_set(rep, bytes)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    // A take seats the bucket the host opened as an owned
                    // handle, which is the guest's to keep, hand back, or
                    // drop — the same seating a lowered argument gets, so
                    // the numbering is one table's whatever opened the
                    // slot.
                    HostFn::WriteTake | HostFn::DeltaTake => {
                        let expected = if host_fn == HostFn::WriteTake {
                            ResourceKind::WriteCell
                        } else {
                            ResourceKind::DeltaCell
                        };
                        let rep = self.resolve_handle(args[0], expected)?;
                        let amount = flat_amount(args[1], args[2]);
                        self.charge_boundary(store, AMOUNT_BOUNDARY_BYTES)?;
                        let result = if host_fn == HostFn::WriteTake {
                            self.host.write_take(rep, amount)
                        } else {
                            self.host.delta_take(rep, amount)
                        };
                        let bucket = result.map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(vec![Value::I32(self.seat_bucket(bucket).cast_signed())])
                    }
                    HostFn::IssuerPut => {
                        let rep = self.resolve_handle(args[0], ResourceKind::Issuer)?;
                        let funds = self.consume_bucket(args[1])?;
                        self.host
                            .issuer_put(rep, funds)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::IssuerMint => {
                        let rep = self.resolve_handle(args[0], ResourceKind::Issuer)?;
                        let mem = self.mem_opt(id)?;
                        let ids = Self::read_guest_bytes(store, mem, args[1], args[2])?;
                        self.charge_boundary(store, ids.len())?;
                        let minted = self
                            .host
                            .issuer_mint(rep, &ids)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(vec![Value::I32(self.seat_bucket(minted).cast_signed())])
                    }
                    HostFn::RangeWriteTake => {
                        let rep = self.resolve_handle(args[0], ResourceKind::RangeWrite)?;
                        let mem = self.mem_opt(id)?;
                        let ids = Self::read_guest_bytes(store, mem, args[1], args[2])?;
                        self.charge_boundary(store, ids.len())?;
                        let taken = self
                            .host
                            .range_take(rep, &ids)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(vec![Value::I32(self.seat_bucket(taken).cast_signed())])
                    }
                    HostFn::RangeWritePut => {
                        let rep = self.resolve_handle(args[0], ResourceKind::RangeWrite)?;
                        let funds = self.consume_bucket(args[1])?;
                        let mem = self.mem_opt(id)?;
                        let value = Self::read_guest_bytes(store, mem, args[2], args[3])?;
                        self.charge_boundary(store, value.len())?;
                        self.host
                            .range_put(rep, funds, value)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::BucketTake => {
                        let rep = self.resolve_handle(args[0], ResourceKind::Bucket)?;
                        let amount = flat_amount(args[1], args[2]);
                        self.charge_boundary(store, AMOUNT_BOUNDARY_BYTES)?;
                        let split = self
                            .host
                            .bucket_take(rep, amount)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(vec![Value::I32(self.seat_bucket(split).cast_signed())])
                    }
                    HostFn::BucketPut => {
                        let rep = self.resolve_handle(args[0], ResourceKind::Bucket)?;
                        let other = self.consume_bucket(args[1])?;
                        self.host
                            .bucket_put(rep, other)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::BucketAmount => {
                        let rep = self.resolve_handle(args[0], ResourceKind::Bucket)?;
                        let amount = self
                            .host
                            .bucket_amount(rep)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        self.charge_boundary(store, AMOUNT_BOUNDARY_BYTES)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_amount(store, mem, args[1], amount)?;
                        Ok(Vec::new())
                    }
                    HostFn::WritePut | HostFn::DeltaPut => {
                        let expected = if host_fn == HostFn::WritePut {
                            ResourceKind::WriteCell
                        } else {
                            ResourceKind::DeltaCell
                        };
                        let rep = self.resolve_handle(args[0], expected)?;
                        let funds = self.consume_bucket(args[1])?;
                        let result = if host_fn == HostFn::WritePut {
                            self.host.write_put(rep, funds)
                        } else {
                            self.host.delta_put(rep, funds)
                        };
                        result.map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::IssuerTake => {
                        let rep = self.resolve_handle(args[0], ResourceKind::Issuer)?;
                        let amount = flat_amount(args[1], args[2]);
                        self.charge_boundary(store, AMOUNT_BOUNDARY_BYTES)?;
                        let bucket = self
                            .host
                            .issuer_take(rep, amount)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(vec![Value::I32(self.seat_bucket(bucket).cast_signed())])
                    }
                    HostFn::ReserveTake => {
                        let rep = self.resolve_handle(args[0], ResourceKind::ReserveCell)?;
                        let bucket = self
                            .host
                            .reserve_take(rep)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(vec![Value::I32(self.seat_bucket(bucket).cast_signed())])
                    }
                    HostFn::DeltaAdd | HostFn::DeltaSub => {
                        let rep = self.resolve_handle(args[0], ResourceKind::DeltaCell)?;
                        let amount = flat_amount(args[1], args[2]);
                        self.charge_boundary(store, AMOUNT_BOUNDARY_BYTES)?;
                        let result = if host_fn == HostFn::DeltaAdd {
                            self.host.delta_add(rep, amount)
                        } else {
                            self.host.delta_sub(rep, amount)
                        };
                        result.map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::RangeReadCount | HostFn::RangeWriteCount => {
                        let expected = if host_fn == HostFn::RangeReadCount {
                            ResourceKind::RangeRead
                        } else {
                            ResourceKind::RangeWrite
                        };
                        let rep = self.resolve_handle(args[0], expected)?;
                        let count = self
                            .host
                            .range_count(rep)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(vec![Value::I32(count.cast_signed())])
                    }
                    HostFn::RangeReadOrder | HostFn::RangeWriteOrder => {
                        let expected = if host_fn == HostFn::RangeReadOrder {
                            ResourceKind::RangeRead
                        } else {
                            ResourceKind::RangeWrite
                        };
                        let rep = self.resolve_handle(args[0], expected)?;
                        let index = args[1].as_i32().cast_unsigned();
                        let order = self
                            .host
                            .range_order(rep, index)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        self.charge_boundary(store, AMOUNT_BOUNDARY_BYTES)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_amount(store, mem, args[2], order)?;
                        Ok(Vec::new())
                    }
                    HostFn::RangeReadEntry | HostFn::RangeWriteEntry => {
                        let expected = if host_fn == HostFn::RangeReadEntry {
                            ResourceKind::RangeRead
                        } else {
                            ResourceKind::RangeWrite
                        };
                        let rep = self.resolve_handle(args[0], expected)?;
                        let index = args[1].as_i32().cast_unsigned();
                        let bytes = self
                            .host
                            .range_entry(rep, index)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        self.charge_boundary(store, bytes.len())?;
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        self.lower_list(modules, store, mem, realloc, &bytes, args[2])?;
                        Ok(Vec::new())
                    }
                    HostFn::RangeWriteSet => {
                        let rep = self.resolve_handle(args[0], ResourceKind::RangeWrite)?;
                        let index = args[1].as_i32().cast_unsigned();
                        let mem = self.mem_opt(id)?;
                        let value = Self::read_guest_bytes(store, mem, args[2], args[3])?;
                        self.charge_boundary(store, value.len())?;
                        self.host
                            .range_set(rep, index, value)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::RangeWriteInsert => {
                        let rep = self.resolve_handle(args[0], ResourceKind::RangeWrite)?;
                        let mem = self.mem_opt(id)?;
                        let order = flat_amount(args[1], args[2]);
                        let value = Self::read_guest_bytes(store, mem, args[3], args[4])?;
                        self.charge_boundary(store, AMOUNT_BOUNDARY_BYTES + value.len())?;
                        self.host
                            .range_insert(rep, order, value)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::RangeWriteRemove => {
                        let rep = self.resolve_handle(args[0], ResourceKind::RangeWrite)?;
                        let index = args[1].as_i32().cast_unsigned();
                        self.host
                            .range_remove(rep, index)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::Randomness => {
                        let draw = self.host.randomness();
                        self.charge_boundary(store, draw.len())?;
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        self.lower_list(modules, store, mem, realloc, &draw, args[0])?;
                        Ok(Vec::new())
                    }
                    HostFn::Hash => {
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        let data = Self::read_guest_bytes(store, mem, args[0], args[1])?;
                        let digest = self.host.hash(&data);
                        self.charge_boundary(store, data.len() + digest.len())?;
                        self.lower_list(modules, store, mem, realloc, &digest, args[2])?;
                        Ok(Vec::new())
                    }
                    HostFn::Emit => {
                        let mem = self.mem_opt(id)?;
                        let event_type = args[0].as_i32().cast_unsigned();
                        let payload = Self::read_guest_bytes(store, mem, args[1], args[2])?;
                        self.charge_boundary(store, payload.len())?;
                        self.host
                            .emit(event_type, payload)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                }
            }
            CoreFuncDef::Alias { .. } => unreachable!("aliases resolve to wasm addresses"),
        }
    }
}
