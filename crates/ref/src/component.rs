//! The component layer: decode, instantiation, and the canonical ABI for the
//! kernel world.
//!
//! Scope is the contract shape the profile admits: one component, core
//! modules linked through core instances, imports drawn from the
//! `hyperscale:kernel` interfaces, canon lower/lift with memory+realloc
//! options, and resource handles with call-scoped borrows. The kernel
//! interfaces' semantics are wired directly against [`KernelHost`] — the
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

use hyperscale_vm_embed::meter::{
    self, AMOUNT_BOUNDARY_BYTES, Exhausted, FuelSink, HostAccess, MeterError, WIDE_BOUNDARY_BYTES,
};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked, KernelHost};
use hyperscale_vm_types::math::{Rounding, U256};
use hyperscale_vm_types::{AbortReason, Drawn, SEED_BYTES};
use wasmparser::{
    CanonicalFunction, CanonicalOption, ComponentAlias, ComponentDefinedType,
    ComponentExternalKind, ComponentType, ComponentTypeRef, ComponentValType, ExternalKind,
    Instance as CoreInstanceReader, InstantiationArgKind, Parser, Payload, PrimitiveValType,
    TypeBounds,
};

use crate::error::{DecodeError, InstantiateError, Trap};
use crate::interp::{
    CanonDispatch, CanonError, ExecError, FuncAddr, Memory, Store, call, instantiate_module,
};
use crate::module::{CoreImportKind, RefModule};
use crate::ops::Value;

/// The state interface's resource types: one per access mode, plus the
/// one that carries value.
///
/// Handles are typed with these, and lifting a borrow of the wrong type
/// traps exactly as the blessed engine's canonical ABI does — the
/// mode-escape trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleKind {
    /// `bucket`: the world's only owned resource, and so the only one a
    /// guest can keep past a call or discard.
    Bucket,
    /// `site`: one declared access, whatever its width and whichever
    /// mode the capability at each element carries.
    Site,
}

impl HandleKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "bucket" => Some(Self::Bucket),
            "site" => Some(Self::Site),
            _ => None,
        }
    }
}

/// A component-level value at the export boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CVal {
    /// `bool`, which only a clause's guard verdict crosses as.
    Bool(bool),
    /// `u32`.
    U32(u32),
    /// `u64`.
    U64(u64),
    /// A borrowed capability handle carrying its host rep and its type.
    Borrow(u32, HandleKind),
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
    /// `list<u64>`: a set of non-fungible instance ids.
    Ids(Vec<u64>),
    /// A declined result: the code the guest returned on the error arm,
    /// an index into its package's error table.
    Declined(u32),
}

impl From<&GuestArg<'_>> for CVal {
    /// The assembled argument as this interpreter's boundary value.
    ///
    /// A capability arrives as a borrow of its mode's resource type, and
    /// the issuance grant as a borrow at the rep the kernel fixes for it —
    /// the one argument whose rep is a constant rather than a table
    /// position, because an invocation is granted at most one.
    fn from(arg: &GuestArg<'_>) -> Self {
        match arg {
            GuestArg::Site { site } => Self::Borrow(*site, HandleKind::Site),
            GuestArg::Bool(taken) => Self::Bool(*taken),
            GuestArg::U64(scalar) => Self::U64(*scalar),
            GuestArg::Address(address) => Self::Address(address.to_bytes()),
            GuestArg::Bytes(bytes) => Self::Bytes(bytes.to_vec()),
            GuestArg::Ids(ids) => Self::Ids(ids.to_vec()),
            GuestArg::Bucket(rep) => Self::Own(*rep),
        }
    }
}

/// A kernel-world import, one variant per function the world declares.
///
/// Named for the function itself, so the mapping in
/// [`RefComponent::host_fn`] is the only place the world's spelling and
/// this crate's meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostFn {
    SiteGet,
    SiteSet,
    SiteClear,
    SiteBalance,
    SiteTake,
    SitePut,
    SiteReserveTake,
    SiteCount,
    SiteCovered,
    SiteOrder,
    SiteEntry,
    SiteEntrySet,
    SiteInsert,
    SiteRemove,
    SiteInstanceTake,
    SiteInstancePut,
    Mint,
    MintInstances,
    Burn,
    BucketTake,
    BucketSplit,
    BucketPut,
    BucketAmount,
    SiteSeal,
    SiteOpenSeal,
    Clock,
    Hash,
    Emit,
    MulDiv,
    GeometricMean,
    FractionCompose,
    FractionCmp,
    FixedPow,
    SiteLen,
    SiteDeclared,
}

/// How many core parameters one kernel operation takes.
const fn host_params(op: HostFn) -> usize {
    match op {
        // The grant is the invocation's, so a burn names the bucket it
        // consumes and nothing else; a site's own count names the site.
        HostFn::Burn | HostFn::SiteLen => 1,
        // Every site operation names the site and the element it acts on
        // before anything of its own. A take's bucket comes back as a
        // flat handle, so it costs no return-area pointer where the read
        // beside it needs one for the amount — which is why each take
        // counts one lower than the read it stands next to.
        HostFn::SiteCount
        | HostFn::SiteCovered
        | HostFn::SiteReserveTake
        | HostFn::SiteClear
        | HostFn::SiteSeal
        | HostFn::SiteDeclared
        | HostFn::BucketAmount
        | HostFn::BucketPut => 2,
        // An issue names the grant it draws on before what it creates —
        // an amount flattening to two, an id list to a pointer and a
        // count.
        HostFn::SiteGet
        | HostFn::SiteBalance
        | HostFn::SiteRemove
        | HostFn::SitePut
        | HostFn::SiteOpenSeal
        | HostFn::BucketTake
        | HostFn::Mint
        | HostFn::MintInstances
        | HostFn::Hash
        | HostFn::Emit => 3,
        HostFn::SiteSet
        | HostFn::SiteTake
        | HostFn::SiteOrder
        | HostFn::SiteEntry
        | HostFn::SiteInstanceTake => 4,
        HostFn::SiteInstancePut | HostFn::SiteEntrySet => 5,
        HostFn::SiteInsert => 6,
        // A `wide` flattens to four `i64`s, and a result wider
        // than one flat value travels through a return pointer
        // the caller appends: `fraction-cmp` returns an enum and
        // so has none, and every other arm here does.
        HostFn::FixedPow => 7,
        HostFn::BucketSplit | HostFn::GeometricMean => 9,
        HostFn::MulDiv => 14,
        HostFn::FractionCmp => 16,
        HostFn::FractionCompose => 17,
        HostFn::Clock => 0,
    }
}

/// A component-level function.
#[derive(Debug, Clone, Copy)]
enum CompFunc {
    /// A kernel import.
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
    ResourceDrop { kind: Option<HandleKind> },
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
    Resource(HandleKind),
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

/// A handle's width in a spilled result: the core `i32` it is.
const HANDLE_BYTES: usize = 4;

/// A list's width in a spilled result: the `(pointer, length)` pair of
/// `i32`s it lowers to.
const LIST_BYTES: usize = 8;

/// One instance id's width, which is also what a `list<u64>` is aligned
/// to.
const ID_BYTES: usize = 8;

/// What a byte list is aligned to, which is nothing.
const BYTE_ALIGN: usize = 1;

/// What a record of `u64`s is aligned to — an `amount` and a wide word
/// alike, since a flat record takes the alignment of its widest field.
const AMOUNT_ALIGN: usize = 8;

/// The bytes a `drawn` occupies in a return area: its case tag padded to
/// the alignment of the word one case carries, then the word.
const DRAWN_BOUNDARY_BYTES: usize = AMOUNT_ALIGN + SEED_BYTES;

/// What a list's `(pointer, length)` pair is aligned to: two `i32`s.
const PAIR_ALIGN: usize = 4;

/// The byte range a guest pointer names, refused unless it is aligned for
/// what sits there and lies within memory.
///
/// Every pointer this interpreter takes from a guest comes through here:
/// a lifted list, the area a spilled result is written to, and what
/// `realloc` hands back. The blessed engine checks both at every one of
/// them, so an interpreter lenient about either would run an artifact the
/// engine turns away — which is a divergence rather than a leniency.
///
/// Both refusals are the ABI declining to read or write through the
/// pointer it was handed, and neither is the guest executing a bad load:
/// no wasm memory instruction ran. So both are a [`CanonError`] and abort
/// as an ABI violation, which is what the blessed engine calls them too.
fn guest_span(
    memory: &[u8],
    ptr: Value,
    size: usize,
    align: usize,
) -> Result<std::ops::Range<usize>, ExecError> {
    let start = usize::try_from(ptr.as_i32().cast_unsigned()).expect("32-bit");
    if start % align != 0 {
        return Err(ExecError::Canon(CanonError::Misaligned));
    }
    match start.checked_add(size) {
        Some(end) if end <= memory.len() => Ok(start..end),
        _ => Err(ExecError::Canon(CanonError::PointerOutOfBounds)),
    }
}

/// The amount a flattened `record { low: u64, high: u64 }` carries.
fn flat_amount(low: Value, high: Value) -> u128 {
    u128::from(low.as_i64().cast_unsigned()) | (u128::from(high.as_i64().cast_unsigned()) << 64)
}

/// The wide word four consecutive flattened arguments carry, starting at
/// `at`, least significant limb first.
fn flat_wide(args: &[Value], at: usize) -> U256 {
    U256::from_limbs([
        args[at].as_i64().cast_unsigned(),
        args[at + 1].as_i64().cast_unsigned(),
        args[at + 2].as_i64().cast_unsigned(),
        args[at + 3].as_i64().cast_unsigned(),
    ])
}

/// The rounding a flattened enum discriminant names.
///
/// Anything past the declared cases is refused as the canonical ABI's
/// invalid-discriminant lift — the violation the engine traps on before
/// a host body runs — rather than resolved to a direction.
fn flat_rounding(value: Value) -> Result<Rounding, ExecError> {
    match value.as_i32() {
        0 => Ok(Rounding::Down),
        1 => Ok(Rounding::Up),
        _ => Err(ExecError::Canon(CanonError::InvalidDiscriminant)),
    }
}

/// A component value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CTy {
    /// `bool`, which only a clause's guard verdict crosses as.
    Bool,
    U32,
    U64,
    List8,
    /// `list<u64>`: an id set, whose elements are eight bytes and whose
    /// allocation is eight-aligned — which is the whole of what
    /// separates its lowering from a byte list's.
    List64,
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
    /// `tuple<…>`: what a method hands back where it is more than one
    /// thing — the byte list it answers with, where it answers one,
    /// ahead of one `own` per edge. Both counts, because that is what
    /// the lift walks.
    Handed {
        /// Whether a byte list leads.
        answer: bool,
        /// How many owned handles follow it.
        edges: u32,
    },
    /// `result<_, u32>`: the refusal channel over what a method hands
    /// back. An error arm says how a method ends and nothing about what
    /// it produces, so the ok arm is the shape it would have been
    /// without one.
    Declinable {
        /// Whether the ok arm's byte list leads.
        answer: bool,
        /// How many owned handles follow it.
        edges: u32,
    },
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
                                let entry = HandleKind::from_name(import.name.name)
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
                ComponentDefinedType::List(ComponentValType::Primitive(PrimitiveValType::U64)) => {
                    CTypeEntry::Defined(CTy::List64)
                }
                ComponentDefinedType::List(_) => {
                    return Err(DecodeError::Unsupported(
                        "list of an unadmitted element".to_string(),
                    ));
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
                    let held: Vec<CTy> = elements
                        .iter()
                        .map(|element| self.value_type(*element))
                        .collect::<Result<_, _>>()?;
                    // The answer leads, so what follows it is edges
                    // whether or not one is there.
                    let (answer, edges) = match held.split_first() {
                        Some((CTy::List8, rest)) => (true, rest),
                        _ => (false, held.as_slice()),
                    };
                    if edges.iter().any(|ty| *ty != CTy::Own) {
                        return Err(DecodeError::Unsupported("tuple element".to_string()));
                    }
                    CTypeEntry::Defined(CTy::Handed {
                        answer,
                        edges: u32::try_from(edges.len())
                            .map_err(|_| DecodeError::Unsupported("tuple arity".to_string()))?,
                    })
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
                        None => CTypeEntry::Defined(CTy::Declinable {
                            answer: false,
                            edges: 0,
                        }),
                        Some(CTy::Own) => CTypeEntry::Defined(CTy::Declinable {
                            answer: false,
                            edges: 1,
                        }),
                        Some(CTy::List8) => CTypeEntry::Defined(CTy::Declinable {
                            answer: true,
                            edges: 0,
                        }),
                        Some(CTy::Handed { answer, edges }) => {
                            CTypeEntry::Defined(CTy::Declinable { answer, edges })
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
            ComponentValType::Primitive(PrimitiveValType::Bool) => Ok(CTy::Bool),
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
                        HandleKind::from_name(name).map_or(CTypeEntry::Other, CTypeEntry::Resource),
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

    #[allow(clippy::too_many_lines)] // one line per kernel import
    fn host_fn(&self, instance: u32, name: &str) -> Result<HostFn, DecodeError> {
        let interface = self
            .import_names
            .get(instance as usize)
            .ok_or_else(|| DecodeError::Malformed("import index".to_string()))?;
        let suffix = interface
            .rsplit_once('/')
            .map_or(interface.as_str(), |(_, s)| s);
        match (suffix, name) {
            ("state", "site-get") => Ok(HostFn::SiteGet),
            ("state", "site-set") => Ok(HostFn::SiteSet),
            ("state", "site-clear") => Ok(HostFn::SiteClear),
            ("state", "site-seal") => Ok(HostFn::SiteSeal),
            ("state", "site-open-seal") => Ok(HostFn::SiteOpenSeal),
            ("state", "site-balance") => Ok(HostFn::SiteBalance),
            ("state", "site-take") => Ok(HostFn::SiteTake),
            ("state", "site-put") => Ok(HostFn::SitePut),
            ("state", "site-reserve-take") => Ok(HostFn::SiteReserveTake),
            ("state", "site-count") => Ok(HostFn::SiteCount),
            ("state", "site-covered") => Ok(HostFn::SiteCovered),
            ("state", "site-order") => Ok(HostFn::SiteOrder),
            ("state", "site-entry") => Ok(HostFn::SiteEntry),
            ("state", "site-entry-set") => Ok(HostFn::SiteEntrySet),
            ("state", "site-insert") => Ok(HostFn::SiteInsert),
            ("state", "site-remove") => Ok(HostFn::SiteRemove),
            ("state", "site-instance-take") => Ok(HostFn::SiteInstanceTake),
            ("state", "site-instance-put") => Ok(HostFn::SiteInstancePut),
            ("state", "site-len") => Ok(HostFn::SiteLen),
            ("state", "site-declared") => Ok(HostFn::SiteDeclared),
            ("state", "bucket-take") => Ok(HostFn::BucketTake),
            ("state", "bucket-split") => Ok(HostFn::BucketSplit),
            ("state", "bucket-put") => Ok(HostFn::BucketPut),
            ("state", "bucket-amount") => Ok(HostFn::BucketAmount),
            ("state", "mint") => Ok(HostFn::Mint),
            ("state", "mint-instances") => Ok(HostFn::MintInstances),
            ("state", "burn") => Ok(HostFn::Burn),
            ("math", "mul-div") => Ok(HostFn::MulDiv),
            ("math", "geometric-mean") => Ok(HostFn::GeometricMean),
            ("math", "fraction-compose") => Ok(HostFn::FractionCompose),
            ("math", "fraction-cmp") => Ok(HostFn::FractionCmp),
            ("math", "fixed-pow") => Ok(HostFn::FixedPow),
            ("env", "clock") => Ok(HostFn::Clock),
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

/// How many core parameters a lowered canon function takes.
///
/// The same answer [`CanonDispatch::param_count`] gives, reachable before
/// a store exists — instantiation is where a disagreement between what a
/// module declared and what the world provides has to be caught, because
/// after it the interpreter has no way to tell the two apart.
fn host_param_count(comp: &RefComponent, id: u32) -> Result<usize, DecodeError> {
    match comp
        .core_funcs
        .get(id as usize)
        .ok_or_else(|| DecodeError::Malformed("core func index".to_string()))?
    {
        CoreFuncDef::ResourceDrop { .. } => Ok(1),
        CoreFuncDef::Lower { func, .. } => match comp
            .comp_funcs
            .get(*func as usize)
            .ok_or_else(|| DecodeError::Malformed("component func index".to_string()))?
        {
            CompFunc::Host(op) => Ok(host_params(*op)),
            CompFunc::Lifted { .. } => Ok(0),
        },
        CoreFuncDef::Alias { .. } => Err(DecodeError::Malformed(
            "an alias is not a canon function".to_string(),
        )),
    }
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
    kind: HandleKind,
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
    /// Handle slots the call being lowered has borrowed.
    ///
    /// An `own` argument comes out of the guest's table, and one lifted
    /// out of a slot the same call is borrowing would leave that borrow
    /// naming an empty slot — so the ABI refuses it. The set is the
    /// call's, cleared as each lowered import begins, because a lend
    /// lasts exactly as long as the call that took it.
    ///
    /// Modelled as the set of slots rather than as a count per handle:
    /// the world has no import taking two borrows of one resource, so
    /// what a count would distinguish has no witness, and what matters is
    /// the question `own` asks — is this slot lent right now.
    lent: Vec<usize>,
    host: H,
}

/// The interpreter's side of the metering seam: the canon's host and the
/// store's counter as the meter's two capabilities. With boundary debt in
/// the one counter, the interpreter's own exhaustion checks see it at the
/// next function entry or loop header, exactly as the engine's do.
struct MeterPort<'a, H> {
    host: &'a mut H,
    store: &'a mut Store,
}

impl<H: KernelHost> HostAccess for MeterPort<'_, H> {
    type Host = H;

    fn host(&mut self) -> &mut H {
        self.host
    }
}

impl<H> FuelSink for MeterPort<'_, H> {
    fn consume(&mut self, fuel: u64) -> Result<(), Exhausted> {
        self.store.fuel_consumed = self.store.fuel_consumed.saturating_add(fuel);
        match self.store.fuel_limit {
            Some(limit) if self.store.fuel_consumed > limit => Err(Exhausted),
            _ => Ok(()),
        }
    }
}

/// A metered failure as an interpreter error.
const fn meter_fault(error: MeterError) -> ExecError {
    match error {
        MeterError::Exhausted => ExecError::Trap(Trap::OutOfFuel),
        MeterError::Refused(reason) => ExecError::Canon(CanonError::Host(reason)),
    }
}

/// An instantiated component.
pub struct RefComponentInstance<'c, H> {
    comp: &'c RefComponent,
    store: Store,
    canon: KernelCanon<'c, H>,
}

impl<'c, H: KernelHost> RefComponentInstance<'c, H> {
    /// Instantiates the component against a host, bounded by `fuel`.
    ///
    /// The budget precedes segment application by signature: applying
    /// active data segments is metered work, and a budget that dies
    /// while it happens traps here — the same site the blessed engine
    /// refuses at — rather than at first function entry.
    ///
    /// # Errors
    ///
    /// [`InstantiateError`] for unresolvable structure or a trap at core
    /// instantiation — an out-of-bounds active segment, or exhaustion —
    /// with the host handed back, since an embedder's session must
    /// survive a refused instantiation.
    ///
    /// # Panics
    ///
    /// Only on index-space overflow past `u32`, which the profile's
    /// structural limits exclude.
    pub fn instantiate(
        comp: &'c RefComponent,
        host: H,
        fuel: u64,
    ) -> Result<Self, (H, InstantiateError)> {
        let (store, resolved_core_funcs, resolved_memories) = match Self::resolve(comp, fuel) {
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
                may_leave: true,
                lent: Vec::new(),
                host,
            },
        })
    }

    /// The host-free half of instantiation: core instances built, index
    /// spaces resolved, active segments applied against the budget.
    #[allow(clippy::too_many_lines)] // the instantiation walk is one pass over defs
    fn resolve(
        comp: &'c RefComponent,
        fuel: u64,
    ) -> Result<(Store, Vec<FuncAddr>, Vec<u32>), InstantiateError> {
        let modules: Vec<&RefModule> = comp.modules.iter().collect();
        let mut store = Store {
            fuel_limit: Some(fuel),
            ..Store::default()
        };
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
                                )
                                .into());
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
                            (CoreImportKind::Func(ty), ResolvedItem::Func(addr)) => {
                                // A kernel import the module declared with
                                // the wrong shape is refused here, where
                                // the blessed engine's linker refuses it:
                                // the world fixes what each operation
                                // takes, and a lowered import whose core
                                // type disagrees would have the
                                // interpreter read arguments the caller
                                // never pushed.
                                if let FuncAddr::Canon(id) = addr {
                                    let declared = m
                                        .types
                                        .get(ty as usize)
                                        .ok_or_else(|| {
                                            DecodeError::Malformed("import type index".to_string())
                                        })?
                                        .params
                                        .len();
                                    let expected = host_param_count(comp, *id)?;
                                    if declared != expected {
                                        return Err(DecodeError::Malformed(format!(
                                            "import {} takes {declared} parameters where the \
                                             kernel world gives it {expected}",
                                            import.name
                                        ))
                                        .into());
                                    }
                                }
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
                                )
                                .into());
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
                    .map_err(InstantiateError::Trap)?;
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
                // The canonical ABI's despecialization: a verdict crosses
                // the core boundary as an `i32` holding zero or one.
                (CVal::Bool(v), CTy::Bool) => flat.push(Value::I32(i32::from(*v))),
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
                        kind: HandleKind::Bucket,
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
                // Lower through the lift options: the guest's realloc
                // allocates, the elements copy in, the (ptr, len) pair
                // joins the flat arguments — exactly the blessed engine's
                // argument path, realloc metered as guest code on both.
                // One arm for both element widths, because the width is
                // the only thing they differ by and a second copy of this
                // is a second place to forget what realloc handed back.
                (CVal::Bytes(_) | CVal::Ids(_), CTy::List8 | CTy::List64) => {
                    let (elements, width) = match arg {
                        CVal::Bytes(bytes) => (bytes.clone(), BYTE_ALIGN),
                        CVal::Ids(ids) => (
                            ids.iter().flat_map(|id| id.to_le_bytes()).collect(),
                            ID_BYTES,
                        ),
                        _ => unreachable!("the arm matched one of the two"),
                    };
                    let count = elements.len() / width;
                    let (Some(mem), Some(realloc)) = (mem_idx, realloc) else {
                        return Err(DecodeError::Unsupported(
                            "list argument without lift options".to_string(),
                        ));
                    };
                    let size =
                        i32::try_from(elements.len()).map_err(|_| DecodeError::ArgumentMismatch)?;
                    let count = i32::try_from(count).map_err(|_| DecodeError::ArgumentMismatch)?;
                    let align = i32::try_from(width).expect("an element width is small");
                    self.canon.may_leave = false;
                    let allocated = call(
                        &modules,
                        &mut self.canon,
                        &mut self.store,
                        realloc,
                        vec![
                            Value::I32(0),
                            Value::I32(0),
                            Value::I32(align),
                            Value::I32(size),
                        ],
                    );
                    self.canon.may_leave = true;
                    let ptr = match allocated {
                        Ok(values) => values.first().copied().unwrap_or(Value::I32(0)).as_i32(),
                        Err(e) => return Ok(Err(e)),
                    };
                    let memory = &mut self.store.memories[mem as usize];
                    let span =
                        match guest_span(&memory.data, Value::I32(ptr), elements.len(), width) {
                            Ok(span) => span,
                            Err(e) => return Ok(Err(e)),
                        };
                    memory.data[span].copy_from_slice(&elements);
                    flat.push(Value::I32(ptr));
                    flat.push(Value::I32(count));
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

            // One own per element, flattened into the result list: a
            // tuple of handles is what a method's edges are, and nothing
            // downstream wants them re-wrapped. One element fits the flat
            // limit and arrives as the handle itself; anything wider
            // spills, and the elements sit at their own alignment in the
            // area the single returned pointer names.
            // One own per edge, flattened into the result list behind
            // the answer where a method has one: nothing downstream
            // wants them re-wrapped. A lone handle fits the flat limit
            // and arrives as itself; anything wider spills, and each
            // piece sits at its own alignment in the area the single
            // returned pointer names.
            [
                CTy::Own
                | CTy::Handed {
                    answer: false,
                    edges: 1,
                },
            ] => Ok(vec![CVal::Own(self.lift_own(area())?)]),
            [CTy::Handed { answer, edges }] => self.lift_handed(mem_idx, area(), *answer, *edges),
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
            [CTy::Declinable { answer, edges }] => {
                if self.discriminant(mem_idx, area())? != 0 {
                    return Ok(vec![CVal::Declined(
                        self.lift_u32(mem_idx, area() + RESULT_PAYLOAD)?,
                    )]);
                }
                self.lift_handed(mem_idx, area() + RESULT_PAYLOAD, *answer, *edges)
            }
            _ => Err(ExecError::Canon(CanonError::Internal("result shape"))),
        }
    }

    /// Lift what a method handed back out of a spilled result: the byte
    /// list it answered with, where it answered one, then one own per
    /// edge behind it, each at its own width.
    fn lift_handed(
        &mut self,
        mem_idx: Option<u32>,
        at: usize,
        answer: bool,
        edges: u32,
    ) -> Result<Vec<CVal>, ExecError> {
        let mut handed = Vec::with_capacity(usize::from(answer) + edges as usize);
        let mut at = at;
        if answer {
            handed.push(CVal::Bytes(self.lift_list(mem_idx, at)?));
            at += LIST_BYTES;
        }
        for _ in 0..edges {
            let handle = self.lift_u32(mem_idx, at)? as usize;
            handed.push(CVal::Own(self.lift_own(handle)?));
            at += HANDLE_BYTES;
        }
        Ok(handed)
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

    /// Invokes an export and folds how it ended into the protocol's
    /// vocabulary: the verdict, total fuel consumed — instantiation
    /// included — and whether the budget exhausted.
    ///
    /// The empty result, the declined code, and a run of edges behind an
    /// optional answer are the only shapes the call convention fixes;
    /// anything else aborts as [`AbortReason::BadReturnShape`]. A name
    /// outside the export table aborts as [`AbortReason::ExportMissing`],
    /// the class the blessed engine's dynamic lookup reports.
    pub fn invoke_kernel(&mut self, export: &str, args: &[CVal]) -> Invocation {
        let outcome = self.invoke(export, args);
        let exhausted = matches!(outcome, Ok(Err(ExecError::Trap(Trap::OutOfFuel))));
        let result = match outcome {
            Ok(Ok(values)) => match values.as_slice() {
                [CVal::Declined(code)] => Invoked::Declined(*code),
                // An answer leads, because the convention puts it first
                // where a method has one — so what follows is edges
                // whether or not one is there.
                values => {
                    let (answer, edges) = match values {
                        [CVal::Bytes(answer), edges @ ..] => (Some(answer.clone()), edges),
                        edges => (None, edges),
                    };
                    edges
                        .iter()
                        .map(|value| match value {
                            CVal::Own(rep) => Ok(*rep),
                            _ => Err(()),
                        })
                        .collect::<Result<Vec<u32>, ()>>()
                        .map_or(Invoked::Aborted(AbortReason::BadReturnShape), |edges| {
                            Invoked::Produced { edges, answer }
                        })
                }
            },
            Ok(Err(error)) => Invoked::Aborted(error.abort_reason()),
            // The export is not in the component's table, which the
            // publish gate admitted it against.
            Err(_) => Invoked::Aborted(AbortReason::ExportMissing),
        };
        Invocation {
            result,
            fuel: self.fuel_consumed(),
            exhausted,
        }
    }

    /// Total fuel consumed: the spec instruction schedule plus the boundary
    /// byte supplement, one counter, matching the blessed runtime's
    /// accounting.
    #[must_use]
    pub const fn fuel_consumed(&self) -> u64 {
        self.store.fuel_consumed
    }

    /// Consumes the instance, returning the host.
    pub fn into_host(self) -> H {
        self.canon.host
    }
}

impl<H: KernelHost> KernelCanon<'_, H> {
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
            kind: HandleKind::Bucket,
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
        if self.lent.contains(&idx) {
            return Err(ExecError::Canon(CanonError::TransferOfLentHandle));
        }
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

    /// Lends a handle to the call being lowered, yielding the rep behind
    /// it. The lend stands until the call ends, which is what stops an
    /// `own` argument beside it from taking the slot away.
    fn resolve_handle(&mut self, index: Value, expected: HandleKind) -> Result<u32, ExecError> {
        let idx = index.as_i32().cast_unsigned() as usize;
        match self.handles.get(idx) {
            Some(Some(h)) if h.live && h.kind == expected => {
                let rep = h.rep;
                self.lent.push(idx);
                Ok(rep)
            }
            Some(Some(h)) if h.live => Err(ExecError::Canon(CanonError::WrongHandleType)),
            _ => Err(ExecError::Canon(CanonError::UnknownHandle)),
        }
    }

    /// The site and element an operation acts through.
    ///
    /// One shape for every width, so the arms below read the same two
    /// arguments whatever the declaration behind them expanded to. What
    /// the capability at that element grants is the session's answer,
    /// held at the operation rather than at the handle.
    fn acting(&mut self, args: &[Value]) -> Result<(u32, u32), ExecError> {
        let site = self.resolve_handle(args[0], HandleKind::Site)?;
        Ok((site, args[1].as_i32().cast_unsigned()))
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
        // What realloc handed back is a guest pointer like any other.
        let span = guest_span(&mem.data, Value::I32(ptr), bytes.len(), BYTE_ALIGN)?;
        mem.data[span].copy_from_slice(bytes);
        // The area the (pointer, length) pair lands in is two `i32`s, so
        // it is four-aligned.
        let ret = guest_span(&mem.data, retptr, 8, PAIR_ALIGN)?;
        let at = ret.start;
        mem.data[at..at + 4].copy_from_slice(&ptr.to_le_bytes());
        mem.data[at + 4..at + 8].copy_from_slice(&len.to_le_bytes());
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
        let at = guest_span(&mem.data, retptr, AMOUNT_BOUNDARY_BYTES, AMOUNT_ALIGN)?;
        mem.data[at].copy_from_slice(&amount.to_le_bytes());
        Ok(())
    }

    /// Writes a wide word whole into the guest's return area.
    ///
    /// Two amounts wide and on the same terms as one: a flat record's
    /// result travels in the area the caller reserved.
    fn write_wide(
        store: &mut Store,
        mem_idx: u32,
        retptr: Value,
        at_offset: usize,
        value: U256,
    ) -> Result<(), ExecError> {
        let mem = &mut store.memories[mem_idx as usize];
        // The offset is a field within the area, and every field of a
        // flat record of `u64`s sits at a multiple of the record's own
        // alignment — so the base is what has to be aligned.
        let base = guest_span(
            &mem.data,
            retptr,
            at_offset + WIDE_BOUNDARY_BYTES,
            AMOUNT_ALIGN,
        )?;
        let at = base.start + at_offset..base.end;
        let (chunks, _) = mem.data[at].as_chunks_mut::<8>();
        for (limb, chunk) in value.limbs().iter().zip(chunks) {
            *chunk = limb.to_le_bytes();
        }
        Ok(())
    }

    /// Lower a `drawn` into the caller's return area.
    ///
    /// A variant of three cases over a payload of four `u64`s: a
    /// one-byte discriminant, the payload aligned to the widest field it
    /// holds, so the case tag sits at the base and the word at the
    /// first eight-byte boundary past it.
    fn write_drawn(
        store: &mut Store,
        mem_idx: u32,
        retptr: Value,
        drawn: Drawn,
    ) -> Result<(), ExecError> {
        let mem = &mut store.memories[mem_idx as usize];
        let span = guest_span(&mem.data, retptr, DRAWN_BOUNDARY_BYTES, AMOUNT_ALIGN)?;
        let base = span.start;
        mem.data[span].fill(0);
        let (tag, word) = match drawn {
            Drawn::Pending => (0u8, None),
            Drawn::Ready(word) => (1, Some(word)),
            Drawn::Expired => (2, None),
        };
        mem.data[base] = tag;
        if let Some(word) = word {
            let at = base + AMOUNT_ALIGN..base + DRAWN_BOUNDARY_BYTES;
            mem.data[at].copy_from_slice(&word);
        }
        Ok(())
    }

    /// The ids a guest's `list<u64>` argument names.
    fn read_guest_ids(
        store: &Store,
        mem_idx: u32,
        ptr: Value,
        len: Value,
    ) -> Result<Vec<u64>, ExecError> {
        let mem = &store.memories[mem_idx as usize];
        let count = usize::try_from(len.as_i32().cast_unsigned()).expect("32-bit");
        let size = count
            .checked_mul(ID_BYTES)
            .ok_or(ExecError::Canon(CanonError::PointerOutOfBounds))?;
        let span = guest_span(&mem.data, ptr, size, ID_BYTES)?;
        Ok(mem.data[span]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|id| u64::from_le_bytes(*id))
            .collect())
    }

    fn read_guest_bytes(
        store: &Store,
        mem_idx: u32,
        ptr: Value,
        len: Value,
    ) -> Result<Vec<u8>, ExecError> {
        let mem = &store.memories[mem_idx as usize];
        let n = usize::try_from(len.as_i32().cast_unsigned()).expect("32-bit");
        let span = guest_span(&mem.data, ptr, n, BYTE_ALIGN)?;
        Ok(mem.data[span].to_vec())
    }
}

impl<H: KernelHost> CanonDispatch for KernelCanon<'_, H> {
    fn param_count(&self, id: u32) -> usize {
        match &self.comp.core_funcs[id as usize] {
            CoreFuncDef::ResourceDrop { .. } => 1,
            // Every site operation names its handle and the element it
            // acts on before anything of its own, so the arity is the
            // operation's alone.
            CoreFuncDef::Lower { func, .. } => match self.comp.comp_funcs[*func as usize] {
                CompFunc::Host(op) => host_params(op),
                CompFunc::Lifted { .. } => 0,
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
                // A lend lasts as long as the call that took it, and this
                // is where one begins.
                self.lent.clear();
                // What reaching the capability took: the site's handle
                // and the element's index. Everything after is the
                // operation's own.
                let after = 2;
                match host_fn {
                    HostFn::Clock => Ok(vec![Value::I64(self.host.clock_ms().cast_signed())]),
                    // The site's own two questions, which name the site
                    // rather than one of its elements.
                    HostFn::SiteLen => {
                        let rep = self.resolve_handle(args[0], HandleKind::Site)?;
                        let len = meter::site_len(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            rep,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(len.cast_signed())])
                    }
                    HostFn::SiteDeclared => {
                        let rep = self.resolve_handle(args[0], HandleKind::Site)?;
                        let index = args[1].as_i32().cast_unsigned();
                        let declared = meter::site_declared(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            rep,
                            index,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(i32::from(declared))])
                    }
                    HostFn::SiteGet => {
                        let (site, element) = self.acting(&args)?;
                        let mut port = MeterPort {
                            host: &mut self.host,
                            store,
                        };
                        let bytes =
                            meter::site_get(&mut port, site, element).map_err(meter_fault)?;
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        self.lower_list(modules, store, mem, realloc, &bytes, args[after])?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteBalance => {
                        let (site, element) = self.acting(&args)?;
                        let held = meter::site_balance(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                        )
                        .map_err(meter_fault)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_amount(store, mem, args[after], held)?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteSet => {
                        let (site, element) = self.acting(&args)?;
                        let mem = self.mem_opt(id)?;
                        let bytes =
                            Self::read_guest_bytes(store, mem, args[after], args[after + 1])?;
                        meter::site_set(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                            bytes,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteClear => {
                        let (site, element) = self.acting(&args)?;
                        meter::site_clear(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    // A take seats the bucket the host opened as an owned
                    // handle, which is the guest's to keep, hand back, or
                    // drop — the same seating a lowered argument gets, so
                    // the numbering is one table's whatever opened the
                    // slot.
                    HostFn::SiteTake => {
                        let (site, element) = self.acting(&args)?;
                        let amount = flat_amount(args[after], args[after + 1]);
                        let mut port = MeterPort {
                            host: &mut self.host,
                            store,
                        };
                        let bucket = meter::site_take(&mut port, site, element, amount)
                            .map_err(meter_fault)?;
                        Ok(vec![Value::I32(self.seat_bucket(bucket).cast_signed())])
                    }
                    HostFn::Burn => {
                        let funds = self.consume_bucket(args[0])?;
                        meter::burn(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            funds,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    HostFn::MintInstances => {
                        let grant = args[0].as_i32().cast_unsigned();
                        let mem = self.mem_opt(id)?;
                        let ids = Self::read_guest_ids(store, mem, args[1], args[2])?;
                        let minted = meter::mint_instances(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            grant,
                            &ids,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(self.seat_bucket(minted).cast_signed())])
                    }
                    HostFn::SiteInstanceTake => {
                        let (site, element) = self.acting(&args)?;
                        let mem = self.mem_opt(id)?;
                        let ids = Self::read_guest_ids(store, mem, args[after], args[after + 1])?;
                        let taken = meter::site_instance_take(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                            &ids,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(self.seat_bucket(taken).cast_signed())])
                    }
                    HostFn::SiteInstancePut => {
                        let (site, element) = self.acting(&args)?;
                        let funds = self.consume_bucket(args[after])?;
                        let mem = self.mem_opt(id)?;
                        let value =
                            Self::read_guest_bytes(store, mem, args[after + 1], args[after + 2])?;
                        meter::site_instance_put(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                            funds,
                            value,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    HostFn::BucketTake => {
                        let rep = self.resolve_handle(args[0], HandleKind::Bucket)?;
                        let amount = flat_amount(args[1], args[2]);
                        let split = meter::bucket_take(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            rep,
                            amount,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(self.seat_bucket(split).cast_signed())])
                    }
                    HostFn::BucketPut => {
                        let rep = self.resolve_handle(args[0], HandleKind::Bucket)?;
                        let other = self.consume_bucket(args[1])?;
                        meter::bucket_put(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            rep,
                            other,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    // Wide arithmetic reaches no state: the meter calls
                    // the shared functions and prices the crossing, and
                    // what the interpreter contributes is the lift — the
                    // rounding discriminant judged before any charge, as
                    // the engine's argument lift runs before its host
                    // body — and the lowering of a result wider than one
                    // flat value.
                    HostFn::MulDiv => {
                        let rounding = flat_rounding(args[12])?;
                        let answer = meter::mul_div(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            flat_wide(&args, 0),
                            flat_wide(&args, 4),
                            flat_wide(&args, 8),
                            rounding,
                        )
                        .map_err(meter_fault)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_wide(store, mem, args[13], 0, answer)?;
                        Ok(Vec::new())
                    }
                    HostFn::GeometricMean => {
                        let answer = meter::geometric_mean(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            flat_wide(&args, 0),
                            flat_wide(&args, 4),
                        )
                        .map_err(meter_fault)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_wide(store, mem, args[8], 0, answer)?;
                        Ok(Vec::new())
                    }
                    HostFn::FractionCompose => {
                        let (num, den) = meter::fraction_compose(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            flat_wide(&args, 0),
                            flat_wide(&args, 4),
                            flat_wide(&args, 8),
                            flat_wide(&args, 12),
                        )
                        .map_err(meter_fault)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_wide(store, mem, args[16], 0, num)?;
                        Self::write_wide(store, mem, args[16], WIDE_BOUNDARY_BYTES, den)?;
                        Ok(Vec::new())
                    }
                    HostFn::FractionCmp => {
                        let order = meter::fraction_cmp(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            flat_wide(&args, 0),
                            flat_wide(&args, 4),
                            flat_wide(&args, 8),
                            flat_wide(&args, 12),
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(match order {
                            std::cmp::Ordering::Less => 0,
                            std::cmp::Ordering::Equal => 1,
                            std::cmp::Ordering::Greater => 2,
                        })])
                    }
                    HostFn::FixedPow => {
                        let rounding = flat_rounding(args[5])?;
                        let answer = meter::fixed_pow(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            flat_wide(&args, 0),
                            args[4].as_i32().cast_unsigned(),
                            rounding,
                        )
                        .map_err(meter_fault)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_wide(store, mem, args[6], 0, answer)?;
                        Ok(Vec::new())
                    }
                    HostFn::BucketSplit => {
                        let rep = self.resolve_handle(args[0], HandleKind::Bucket)?;
                        let split = meter::bucket_split(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            rep,
                            flat_wide(&args, 1),
                            flat_wide(&args, 5),
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(self.seat_bucket(split).cast_signed())])
                    }
                    HostFn::BucketAmount => {
                        let rep = self.resolve_handle(args[0], HandleKind::Bucket)?;
                        let amount = meter::bucket_amount(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            rep,
                        )
                        .map_err(meter_fault)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_amount(store, mem, args[1], amount)?;
                        Ok(Vec::new())
                    }
                    HostFn::SitePut => {
                        let (site, element) = self.acting(&args)?;
                        let funds = self.consume_bucket(args[after])?;
                        let mut port = MeterPort {
                            host: &mut self.host,
                            store,
                        };
                        meter::site_put(&mut port, site, element, funds).map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    HostFn::Mint => {
                        let grant = args[0].as_i32().cast_unsigned();
                        let amount = flat_amount(args[1], args[2]);
                        let bucket = meter::mint(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            grant,
                            amount,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(self.seat_bucket(bucket).cast_signed())])
                    }
                    HostFn::SiteReserveTake => {
                        let (site, element) = self.acting(&args)?;
                        let bucket = meter::site_reserve_take(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(self.seat_bucket(bucket).cast_signed())])
                    }
                    HostFn::SiteCount => {
                        let (site, element) = self.acting(&args)?;
                        let count = meter::site_count(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(count.cast_signed())])
                    }
                    HostFn::SiteCovered => {
                        let (site, element) = self.acting(&args)?;
                        let covered = meter::site_covered(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                        )
                        .map_err(meter_fault)?;
                        Ok(vec![Value::I32(i32::from(covered))])
                    }
                    HostFn::SiteOrder => {
                        let (site, element) = self.acting(&args)?;
                        let index = args[after].as_i32().cast_unsigned();
                        let order = meter::site_order(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                            index,
                        )
                        .map_err(meter_fault)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_amount(store, mem, args[after + 1], order)?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteEntry => {
                        let (site, element) = self.acting(&args)?;
                        let index = args[after].as_i32().cast_unsigned();
                        let bytes = meter::site_entry(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                            index,
                        )
                        .map_err(meter_fault)?;
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        self.lower_list(modules, store, mem, realloc, &bytes, args[after + 1])?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteEntrySet => {
                        let (site, element) = self.acting(&args)?;
                        let index = args[after].as_i32().cast_unsigned();
                        let mem = self.mem_opt(id)?;
                        let value =
                            Self::read_guest_bytes(store, mem, args[after + 1], args[after + 2])?;
                        meter::site_entry_set(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                            index,
                            value,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteInsert => {
                        let (site, element) = self.acting(&args)?;
                        let mem = self.mem_opt(id)?;
                        let order = flat_amount(args[after], args[after + 1]);
                        let value =
                            Self::read_guest_bytes(store, mem, args[after + 2], args[after + 3])?;
                        meter::site_insert(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                            order,
                            value,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteRemove => {
                        let (site, element) = self.acting(&args)?;
                        let index = args[after].as_i32().cast_unsigned();
                        meter::site_remove(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                            index,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteSeal => {
                        let (site, element) = self.acting(&args)?;
                        meter::site_seal(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                    HostFn::SiteOpenSeal => {
                        let (site, element) = self.acting(&args)?;
                        let drawn = meter::site_open_seal(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            site,
                            element,
                        )
                        .map_err(meter_fault)?;
                        let mem = self.mem_opt(id)?;
                        Self::write_drawn(store, mem, args[after], drawn)?;
                        Ok(Vec::new())
                    }
                    HostFn::Hash => {
                        let (mem, realloc) = (self.mem_opt(id)?, self.realloc_opt(id)?);
                        let data = Self::read_guest_bytes(store, mem, args[0], args[1])?;
                        let digest = meter::hash(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            &data,
                        )
                        .map_err(meter_fault)?;
                        self.lower_list(modules, store, mem, realloc, &digest, args[2])?;
                        Ok(Vec::new())
                    }
                    HostFn::Emit => {
                        let mem = self.mem_opt(id)?;
                        let event_type = args[0].as_i32().cast_unsigned();
                        let payload = Self::read_guest_bytes(store, mem, args[1], args[2])?;
                        meter::emit(
                            &mut MeterPort {
                                host: &mut self.host,
                                store,
                            },
                            event_type,
                            payload,
                        )
                        .map_err(meter_fault)?;
                        Ok(Vec::new())
                    }
                }
            }
            CoreFuncDef::Alias { .. } => unreachable!("aliases resolve to wasm addresses"),
        }
    }
}
