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

use std::collections::HashMap;

use wasmparser::{
    CanonicalFunction, CanonicalOption, ComponentAlias, ComponentDefinedType,
    ComponentExternalKind, ComponentType, ComponentTypeRef, ComponentValType, ExternalKind,
    Instance as CoreInstanceReader, InstantiationArgKind, Parser, Payload, PrimitiveValType,
};

use crate::error::{DecodeError, Trap};
use crate::interp::{
    CanonDispatch, CanonError, ExecError, FuncAddr, Store, call, instantiate_module,
};
use crate::module::{CoreImportKind, RefModule};
use crate::ops::Value;

/// The host surface behind the kernel world.
///
/// Mirrors the runtime's trait — same operations, same deterministic
/// refusal messages — so one host drives both implementations. Every
/// `Err` is a kernel refusal that traps with its message.
#[allow(missing_docs)] // mirrors the documented runtime trait method for method
#[allow(clippy::missing_errors_doc)] // every Err is a deterministic kernel refusal
pub trait RefKernelHost {
    fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, String>;
    fn snap_cell(&mut self, rep: u32) -> Result<Vec<u8>, String>;
    fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, String>;
    fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), String>;
    fn delta_add(&mut self, rep: u32, amount: &[u8]) -> Result<(), String>;
    fn delta_sub(&mut self, rep: u32, amount: &[u8]) -> Result<(), String>;
    fn reserve_amount(&mut self, rep: u32) -> Result<Vec<u8>, String>;
    fn range_count(&mut self, rep: u32) -> Result<u32, String>;
    fn range_order(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, String>;
    fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, String>;
    fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), String>;
    fn range_insert(&mut self, rep: u32, order: &[u8], value: Vec<u8>) -> Result<(), String>;
    fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), String>;
    /// The transaction clock in milliseconds.
    fn clock_ms(&self) -> u64;
    /// The transaction's randomness draw.
    fn randomness(&self) -> [u8; 32];
    /// The protocol hash function.
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

/// The state interface's resource types: one per access mode.
///
/// Handles are typed with these, and lifting a borrow of the wrong type
/// traps exactly as the blessed engine's canonical ABI does — the
/// mode-escape trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// `read-cell`.
    ReadCell,
    /// `snap-cell`.
    SnapCell,
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
            "read-cell" => Some(Self::ReadCell),
            "snap-cell" => Some(Self::SnapCell),
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
    /// A `list<u8>` value at the export boundary.
    Bytes(Vec<u8>),
}

/// A kernel-world import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostFn {
    ReadCellGet,
    SnapCellGet,
    WriteCellGet,
    WriteCellSet,
    DeltaAdd,
    DeltaSub,
    ReserveAmount,
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

/// A component value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CTy {
    U32,
    U64,
    List8,
    Borrow,
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
                                comp.import_names.push(import.name.0.to_string());
                            }
                            ComponentTypeRef::Type(_) => {
                                comp.types.push(
                                    ResourceKind::from_name(import.name.0)
                                        .map_or(CTypeEntry::Other, CTypeEntry::Resource),
                                );
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
                                comp.exports.insert(export.name.0.to_string(), export.index);
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
                ComponentDefinedType::Borrow(_) => CTypeEntry::Defined(CTy::Borrow),
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
            ("state", "snap-cell-get") => Ok(HostFn::SnapCellGet),
            ("state", "write-cell-get") => Ok(HostFn::WriteCellGet),
            ("state", "write-cell-set") => Ok(HostFn::WriteCellSet),
            ("state", "delta-cell-add") => Ok(HostFn::DeltaAdd),
            ("state", "delta-cell-sub") => Ok(HostFn::DeltaSub),
            ("state", "reserve-cell-amount") => Ok(HostFn::ReserveAmount),
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
}

/// The canonical-ABI runtime: handle table plus the host, implementing canon
/// dispatch for the interpreter.
struct KernelCanon<'c, H> {
    comp: &'c RefComponent,
    resolved_core_funcs: Vec<FuncAddr>,
    resolved_memories: Vec<u32>,
    handles: Vec<Handle>,
    /// Bytes crossing the canonical ABI boundary, mirroring the runtime's
    /// per-byte fuel supplement.
    boundary_bytes: u64,
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
    /// [`DecodeError`] for unresolvable structure; a trap if an active
    /// segment is out of bounds at core instantiation.
    ///
    /// # Panics
    ///
    /// Only on index-space overflow past `u32`, which the profile's
    /// structural limits exclude.
    #[allow(clippy::too_many_lines)] // the instantiation walk is one pass over defs
    pub fn instantiate(comp: &'c RefComponent, host: H) -> Result<Self, DecodeError> {
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

        Ok(Self {
            comp,
            store,
            canon: KernelCanon {
                comp,
                resolved_core_funcs,
                resolved_memories: resolved_memories_by_alias,
                handles: Vec::new(),
                boundary_bytes: 0,
                host,
            },
        })
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

        self.canon.handles.clear();
        let modules: Vec<&RefModule> = self.comp.modules.iter().collect();
        self.store.depth = 0;
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
                    let idx = u32::try_from(self.canon.handles.len()).expect("bounded");
                    self.canon.handles.push(Handle {
                        rep: *rep,
                        kind: *kind,
                        live: true,
                    });
                    flat.push(Value::I32(idx.cast_signed()));
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
                    let allocated = call(
                        &modules,
                        &mut self.canon,
                        &mut self.store,
                        realloc,
                        vec![Value::I32(0), Value::I32(0), Value::I32(1), Value::I32(len)],
                    );
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
                if self.canon.handles.iter().any(|h| h.live) {
                    Err(ExecError::Canon(CanonError::BorrowsRemain))
                } else {
                    let lifted = self.lift_results(&ctype, &values, mem_idx);
                    if let Ok(_) = &lifted
                        && let Some(index) = post_return
                        && let Some(addr) =
                            self.canon.resolved_core_funcs.get(index as usize).copied()
                    {
                        let modules: Vec<&RefModule> = self.comp.modules.iter().collect();
                        if let Err(e) =
                            call(&modules, &mut self.canon, &mut self.store, addr, values)
                        {
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
    /// scalars come back flat; a list result spills to a return area the
    /// single returned pointer names.
    fn lift_results(
        &self,
        ctype: &CType,
        values: &[Value],
        mem_idx: Option<u32>,
    ) -> Result<Vec<CVal>, ExecError> {
        match ctype.results.as_slice() {
            [] => Ok(Vec::new()),
            [CTy::U32] => Ok(vec![CVal::U32(
                values.first().map_or(0, |v| v.as_i32().cast_unsigned()),
            )]),
            [CTy::U64] => Ok(vec![CVal::U64(
                values.first().map_or(0, |v| v.as_i64().cast_unsigned()),
            )]),
            [CTy::List8] => {
                let area = values.first().map_or(0, |v| v.as_i32().cast_unsigned()) as usize;
                let Some(mem) = mem_idx else {
                    return Err(ExecError::Canon(CanonError::Internal(
                        "list result without a memory option",
                    )));
                };
                let memory = &self.store.memories[mem as usize];
                if area + 8 > memory.data.len() {
                    return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
                }
                let ptr =
                    u32::from_le_bytes(memory.data[area..area + 4].try_into().expect("4 bytes"))
                        as usize;
                let len = u32::from_le_bytes(
                    memory.data[area + 4..area + 8].try_into().expect("4 bytes"),
                ) as usize;
                let Some(end) = ptr.checked_add(len) else {
                    return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
                };
                if end > memory.data.len() {
                    return Err(ExecError::Trap(Trap::MemoryOutOfBounds));
                }
                Ok(vec![CVal::Bytes(memory.data[ptr..end].to_vec())])
            }
            _ => Err(ExecError::Canon(CanonError::Internal("result shape"))),
        }
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

    fn resolve_handle(&self, index: Value, expected: ResourceKind) -> Result<u32, ExecError> {
        let idx = index.as_i32().cast_unsigned() as usize;
        match self.handles.get(idx) {
            Some(h) if h.live && h.kind == expected => Ok(h.rep),
            Some(h) if h.live => Err(ExecError::Canon(CanonError::WrongHandleType)),
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
        let results = call(
            modules,
            self,
            store,
            realloc,
            vec![Value::I32(0), Value::I32(0), Value::I32(1), Value::I32(len)],
        )?;
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
                CompFunc::Host(
                    HostFn::RangeReadCount | HostFn::RangeWriteCount | HostFn::Randomness,
                ) => 1,
                CompFunc::Host(
                    HostFn::ReadCellGet
                    | HostFn::SnapCellGet
                    | HostFn::WriteCellGet
                    | HostFn::ReserveAmount
                    | HostFn::RangeWriteRemove,
                ) => 2,
                CompFunc::Host(
                    HostFn::WriteCellSet
                    | HostFn::DeltaAdd
                    | HostFn::DeltaSub
                    | HostFn::RangeReadOrder
                    | HostFn::RangeReadEntry
                    | HostFn::RangeWriteOrder
                    | HostFn::RangeWriteEntry
                    | HostFn::Hash,
                ) => 3,
                CompFunc::Host(HostFn::RangeWriteSet) => 4,
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
        let def = self.comp.core_funcs[id as usize].clone();
        match def {
            CoreFuncDef::ResourceDrop { kind } => {
                let idx = args[0].as_i32().cast_unsigned() as usize;
                match self.handles.get_mut(idx) {
                    Some(h) if h.live && kind.is_none_or(|k| k == h.kind) => {
                        h.live = false;
                        Ok(Vec::new())
                    }
                    Some(h) if h.live => Err(ExecError::Canon(CanonError::WrongHandleType)),
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
                    HostFn::ReadCellGet
                    | HostFn::SnapCellGet
                    | HostFn::WriteCellGet
                    | HostFn::ReserveAmount => {
                        let expected = match host_fn {
                            HostFn::ReadCellGet => ResourceKind::ReadCell,
                            HostFn::SnapCellGet => ResourceKind::SnapCell,
                            HostFn::WriteCellGet => ResourceKind::WriteCell,
                            _ => ResourceKind::ReserveCell,
                        };
                        let rep = self.resolve_handle(args[0], expected)?;
                        let result = match host_fn {
                            HostFn::ReadCellGet => self.host.read_cell(rep),
                            HostFn::SnapCellGet => self.host.snap_cell(rep),
                            HostFn::WriteCellGet => self.host.write_cell_get(rep),
                            _ => self.host.reserve_amount(rep),
                        };
                        let bytes = result.map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        self.boundary_bytes += bytes.len() as u64;
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        self.lower_list(modules, store, mem, realloc, &bytes, args[1])?;
                        Ok(Vec::new())
                    }
                    HostFn::WriteCellSet => {
                        let rep = self.resolve_handle(args[0], ResourceKind::WriteCell)?;
                        let mem = self.mem_opt(id)?;
                        let bytes = Self::read_guest_bytes(store, mem, args[1], args[2])?;
                        self.boundary_bytes += bytes.len() as u64;
                        self.host
                            .write_cell_set(rep, bytes)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::DeltaAdd | HostFn::DeltaSub => {
                        let rep = self.resolve_handle(args[0], ResourceKind::DeltaCell)?;
                        let mem = self.mem_opt(id)?;
                        let amount = Self::read_guest_bytes(store, mem, args[1], args[2])?;
                        self.boundary_bytes += amount.len() as u64;
                        let result = if host_fn == HostFn::DeltaAdd {
                            self.host.delta_add(rep, &amount)
                        } else {
                            self.host.delta_sub(rep, &amount)
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
                    HostFn::RangeReadOrder
                    | HostFn::RangeReadEntry
                    | HostFn::RangeWriteOrder
                    | HostFn::RangeWriteEntry => {
                        let expected = match host_fn {
                            HostFn::RangeReadOrder | HostFn::RangeReadEntry => {
                                ResourceKind::RangeRead
                            }
                            _ => ResourceKind::RangeWrite,
                        };
                        let rep = self.resolve_handle(args[0], expected)?;
                        let index = args[1].as_i32().cast_unsigned();
                        let result = match host_fn {
                            HostFn::RangeReadOrder | HostFn::RangeWriteOrder => {
                                self.host.range_order(rep, index)
                            }
                            _ => self.host.range_entry(rep, index),
                        };
                        let bytes = result.map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        self.boundary_bytes += bytes.len() as u64;
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        self.lower_list(modules, store, mem, realloc, &bytes, args[2])?;
                        Ok(Vec::new())
                    }
                    HostFn::RangeWriteSet => {
                        let rep = self.resolve_handle(args[0], ResourceKind::RangeWrite)?;
                        let index = args[1].as_i32().cast_unsigned();
                        let mem = self.mem_opt(id)?;
                        let value = Self::read_guest_bytes(store, mem, args[2], args[3])?;
                        self.boundary_bytes += value.len() as u64;
                        self.host
                            .range_set(rep, index, value)
                            .map_err(|m| ExecError::Canon(CanonError::Host(m)))?;
                        Ok(Vec::new())
                    }
                    HostFn::RangeWriteInsert => {
                        let rep = self.resolve_handle(args[0], ResourceKind::RangeWrite)?;
                        let mem = self.mem_opt(id)?;
                        let order = Self::read_guest_bytes(store, mem, args[1], args[2])?;
                        let value = Self::read_guest_bytes(store, mem, args[3], args[4])?;
                        self.boundary_bytes += order.len() as u64 + value.len() as u64;
                        self.host
                            .range_insert(rep, &order, value)
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
                        self.boundary_bytes += draw.len() as u64;
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        self.lower_list(modules, store, mem, realloc, &draw, args[0])?;
                        Ok(Vec::new())
                    }
                    HostFn::Hash => {
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        let data = Self::read_guest_bytes(store, mem, args[0], args[1])?;
                        let digest = self.host.hash(&data);
                        self.boundary_bytes += data.len() as u64 + digest.len() as u64;
                        self.lower_list(modules, store, mem, realloc, &digest, args[2])?;
                        Ok(Vec::new())
                    }
                }
            }
            CoreFuncDef::Alias { .. } => unreachable!("aliases resolve to wasm addresses"),
        }
    }
}
