//! Deploy-time totality checking.
//!
//! A method marked total promises its callers that it cannot come back
//! with a refusal or a fault. Two things could break that promise here
//! and the vocabulary sees only one of them: a gate turns callers away
//! before the body runs, which a signature's accessibility states, and a
//! trap leaves the type system entirely and states nothing anywhere.
//! This module answers the second — a scan of a function body for the
//! operators that can fault, so the verdict is read off the code rather
//! than taken from the package that would benefit from it.
//!
//! There is no third the scan must find. A method that can decline says
//! so in its own signature — the `result<_, u32>` error arm is the
//! declared refusal channel, and the gate reads a totality claim against
//! it — so declining is a fact the vocabulary already states. What no
//! signature states is trapping, and that is the whole of what the scan
//! answers.
//!
//! The scan is a membership test, not an analysis. Proving an arbitrary
//! body cannot fault is undecidable, and approximating it well is a
//! research problem; deciding whether a body stays inside a vocabulary
//! that has no faulting member is a walk over its operators. What that
//! costs is expressiveness — a body that could never fault in practice is
//! refused for using an instruction that could in principle — and what it
//! buys is that a granted mark means something checkable.
//!
//! Refusal is cheap on purpose. A method that fails this check is not
//! broken and its package still deploys: it classifies as
//! [`Infallible`](hyperscale_vm_effects::Totality::Infallible) at best, so
//! what it loses is the decomposition an outbound leg would have had.
//! That asymmetry is what lets the check ship while it is still
//! conservative.
//!
//! ## Linear memory is taken as safe, and that is a judgment
//!
//! Every load and store can fault on an out-of-bounds address, so a scan
//! that treated them as trap-capable would refuse every body that touches
//! memory, which is every body. The check instead relies on the
//! toolchain: safe Rust compiled to wasm accesses only memory its own
//! allocator manages, and the bounds checks it emits fault through
//! `unreachable` rather than through the access itself. So the
//! `unreachable` ban below is what covers indexing, and a raw
//! out-of-bounds store could only come from unsafe code the profile does
//! not otherwise restrict.
//!
//! This is the check's weakest link and it is deliberate. It is sound for
//! the stdlib, which is the code the mark is granted to today, and it
//! wants revisiting before an untrusted package can earn one.
//!
//! ## The canonical ABI's glue is excluded, and that is the second
//!
//! Measured against the account guest, every export but the two that read
//! and return nothing fails on `unreachable` — and the failure is never in
//! the authored body. It is in the allocator the ABI calls to move a
//! `list<u8>` across the boundary, which panics on allocation failure, and
//! which every export that carries a value therefore reaches. Checking it
//! would deny the mark to every method in the language, forever, for a
//! reason no author can act on.
//!
//! So the closure of the ABI's support functions is excluded from the
//! walk, on the same footing as the imports: allocation failure is a
//! resource bound the boundary discharges, exactly as fuel exhaustion is,
//! and a leg whose memory is pre-sized cannot reach it.
//!
//! **Which functions those are is read from the component's own wiring,
//! never from their names.** A `cabi_` prefix is something an author
//! chooses, so excluding by prefix would let a package export its
//! panicking helper under that name and have the scan look away — a hole
//! anyone reading this file could walk through. What a `canon lift`
//! designates is a role rather than a name: the runtime calls that
//! function to allocate for every value crossing the boundary. A package
//! can still point the role at a body of its own, and then that body has
//! to serve as the allocator, which leaves it holding the gap the honest
//! allocator already has instead of opening a new one.
//!
//! The same holds for the body the scan starts from, and for the same
//! reason. A method's name is the component's, and which core function
//! runs under it is what the wiring says: the export names a component
//! function, a lift defines it over a core function, and that core
//! function is an alias of a core instance's export. Reading a core
//! export that merely shares the method's name would let a package put a
//! harmless body under it and be judged on that instead of on the one
//! that runs. So [`Wiring`] resolves both questions, and neither is
//! answered by comparing a name to a name.
//!
//! What the exclusion costs is still real: a body that panics *through*
//! the glue is not caught, and a helper the allocator and an authored
//! method both call is set aside on the allocator's account. Closing that
//! means a panic-free allocator rather than a cleverer scan.

use std::collections::BTreeSet;
use std::ops::Range;

use wasmparser::{
    BinaryReaderError, CanonicalFunction, CanonicalOption, ComponentAlias, ComponentExternalKind,
    ComponentOuterAliasKind, ComponentTypeRef, ConstExpr, ElementItems, ElementKind, ExternalKind,
    FunctionBody, Instance, InstantiationArgKind, Operator, Parser, Payload, TypeRef,
};

/// The kernel-world imports a total body may call, each with the
/// invariant that discharges its refusals before the body starts.
///
/// The list is an allowlist on purpose: a host call outside it is
/// refused, so a new world function stays outside the mark's reach until
/// someone writes down why it cannot refuse on a total leg. What every
/// entry leans on first is materialization — a handle the body holds
/// names a cell its declared effect set materialized, so existence and
/// mode are settled before the first instruction runs — and the
/// per-entry comments carry what each operation needs past that.
const DISCHARGED: &[(&str, &str)] = &[
    // A get reads the cell its handle names; materialization is the
    // whole of what it needs.
    ("state", "capability-get"),
    // A set stores the bytes it is handed with no judgment at the call;
    // what a receipt may carry is judged at its own boundary.
    ("state", "capability-set"),
    // A clear ends a leaf the handle already holds exclusively; there
    // is nothing to judge that materialization did not.
    ("state", "capability-clear"),
    // A denominated cell holds an amount: value enters one only through
    // movements, so the read cannot meet bytes — a cell that did would
    // be a defect in state, not a refusal the call can reach.
    ("state", "capability-balance"),
    // What an edge carries is the edge's own fact.
    ("state", "bucket-amount"),
    // A credit of conserved value: the cell's denomination was judged at
    // admission against what the edge carries, and supply linearity
    // bounds any balance plus any bucket at the accumulator's width — a
    // sum past it would need value no mint ever created. Refused at the
    // call for an exclusive hold and at the fold for a movement, and
    // neither refusal is one this leg can reach.
    ("state", "capability-put"),
    // A count takes no index, so there is no bound to fall outside; the
    // coverage question is answered from the same page and its probe.
    ("state", "capability-count"),
    ("state", "capability-covered"),
    // Total on every input; the arithmetic that refuses a divisor or a
    // width stays out, because those are runtime values no declaration
    // speaks about.
    ("math", "geometric-mean"),
    // Environment reads with no failure mode at all.
    ("env", "clock"),
    ("crypto", "hash"),
    // The one admission that rests on the mark's envelope rather than on
    // a kernel discharge: the caps — type, count, payload — can refuse
    // in general. The mark is granted to protocol code only (the gate
    // refuses a published totality claim outright), and the protocol's
    // total bodies emit fixed-width payloads from loop-free code, so the
    // count is bounded by call sites and a decomposed leg's session
    // starts at zero events. Nothing here proves that; the grant's
    // review does.
    ("events", "emit"),
];

/// The resources whose `resource.drop` a total body may reach: every
/// handle the world lends, whose destructor releases a table slot and
/// judges nothing. The bucket is one of them on the same terms as the
/// rest — its destructor releases the slot when there is nothing left to
/// account for and holds on to it when there is, and either way it
/// returns no verdict a body could trip over. Whether the transaction
/// lost value is settled once, at the close, over the whole table.
const DISCHARGED_DROPS: &[(&str, &str)] = &[
    ("state", "capability"),
    ("state", "run"),
    ("state", "issuer"),
    ("state", "bucket"),
];

/// Why a body cannot carry the total mark.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TotalityError {
    /// The body can reach `unreachable`, which is where every Rust panic
    /// lands: a failed bounds check, an unwrap on nothing, an overflow
    /// the build checks for. Its absence is the single strongest thing
    /// the scan learns, because the compiler emitting no panic path is
    /// the compiler having proven there is none.
    #[error("the body can reach `unreachable`")]
    Unreachable,
    /// An integer division or remainder whose divisor is not a non-zero
    /// literal. Division by zero faults, and only a constant divisor
    /// rules it out where the scan can see.
    #[error("integer division by a value the scan cannot prove non-zero")]
    DivisionByUnprovenDivisor,
    /// An indirect call, which faults on a null table slot or a mismatched
    /// signature. It also hides the callee, so the transitive body the
    /// mark speaks for would not be knowable.
    #[error("an indirect call, whose callee is neither known nor guaranteed to exist")]
    IndirectCall,
    /// A loop, whose trip count the scan cannot bound and therefore whose
    /// fuel it cannot bound either. Totality includes not exhausting the
    /// fuel the transaction pre-charged, which needs a static ceiling.
    #[error("a loop, whose fuel cost has no static bound")]
    UnboundedLoop,
    /// The component exports no such method, or its wiring leads to no
    /// core body.
    #[error("no exported method {0:?} the wiring resolves to a body")]
    NoSuchExport(String),
    /// A call to a host function that can fault for a reason no
    /// declaration discharges.
    #[error("a call to `{0}`, whose refusal no declared effect set discharges")]
    FaultingHostCall(String),
    /// The body could not be decoded.
    #[error("undecodable body: {0}")]
    Undecodable(String),
}

/// Whether `body` stays inside the vocabulary that has no faulting member.
///
/// The divisor rule is a peephole: an integer division is admitted when
/// the operator immediately before it pushed a non-zero constant, which is
/// the shape a division by a fixed denominator compiles to. Anything else
/// — a divisor read from memory, computed, or passed in — is refused,
/// since the scan has no way to know it is non-zero.
///
/// # Errors
///
/// The first [`TotalityError`] the walk reaches. The scan stops there:
/// one faulting operator is enough to deny the mark, and reporting the
/// rest would not change the verdict.
pub fn check_body(body: &FunctionBody<'_>) -> Result<(), TotalityError> {
    let reader = body
        .get_operators_reader()
        .map_err(|e| TotalityError::Undecodable(e.to_string()))?;

    let mut previous: Option<Operator<'_>> = None;
    for op in reader {
        let op = op.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
        match op {
            Operator::Unreachable => return Err(TotalityError::Unreachable),
            Operator::CallIndirect { .. } => return Err(TotalityError::IndirectCall),
            Operator::Loop { .. } => return Err(TotalityError::UnboundedLoop),
            Operator::I32DivS
            | Operator::I32DivU
            | Operator::I32RemS
            | Operator::I32RemU
            | Operator::I64DivS
            | Operator::I64DivU
            | Operator::I64RemS
            | Operator::I64RemU
                if !divisor_is_non_zero(previous.as_ref()) =>
            {
                return Err(TotalityError::DivisionByUnprovenDivisor);
            }
            _ => {}
        }
        previous = Some(op);
    }
    Ok(())
}

/// Whether every function reachable from `entry` stays inside the
/// vocabulary, walking the module's own call graph.
///
/// The mark speaks for a transitive body, not for one function: a method
/// whose own operators are harmless but which calls something that panics
/// can still panic. So the check follows every direct call from the entry
/// and refuses if any body it reaches does.
///
/// **A host call is admitted only where a declaration discharges its
/// refusals, and a bare core module gives that judgment nothing to work
/// with.** Which interface an import reaches is the component's wiring
/// to answer — a module's own import names are whatever the guest chose
/// — so with no component around it, every import call is refused here:
/// what cannot be identified cannot be discharged. The per-function
/// verdicts live in [`DISCHARGED`] and are applied by [`check_method`],
/// which has a wiring to resolve them through.
///
/// `entry` indexes the module's whole function space — imports first,
/// then defined functions — the same space [`Operator::Call`] uses.
///
/// Nothing is set aside either. A bare core module has no canonical
/// section, so there is no lift to designate a realloc and no name alone
/// can stand in for one; the glue exclusion belongs to [`check_method`]
/// on the same grounds as the import verdicts.
///
/// # Errors
///
/// The first [`TotalityError`] any reachable body yields, or
/// [`TotalityError::Undecodable`] if the module does not parse.
pub fn check_reachable(module: &[u8], entry: u32) -> Result<(), TotalityError> {
    let parsed = Module::parse(module)?;
    let undischarged = (0..u32::try_from(parsed.imports.len()).unwrap_or(u32::MAX)).collect();
    parsed.walk(entry, &BTreeSet::new(), &undischarged)
}

/// Whether the method a package exports as `method` can carry the mark.
///
/// Takes the artifact as deployed, and finds the body through the
/// component's own wiring: the export names a component function, a
/// `canon lift` defines it over a core function, and that core function
/// is an alias of some core instance's export. **Nothing here matches a
/// core export against the method's name.** A core module may export
/// whatever names it likes, so a package that exports a harmless
/// function under the name of the method it lifts elsewhere would have
/// the scan read the decoy and grant the mark to the body beside it —
/// the same hole the ABI support set refuses to open, and it has to be
/// shut on the same terms.
///
/// # Errors
///
/// [`TotalityError::NoSuchExport`] if the component exports no such
/// method, or if its wiring does not lead to a core body, or whatever
/// the walk from that body yields.
pub fn check_method(artifact: &[u8], method: &str) -> Result<(), TotalityError> {
    let wiring = Wiring::read(artifact)?;
    let missing = || TotalityError::NoSuchExport(method.to_string());
    let (instance, module, export) = wiring.entry(method).ok_or_else(missing)?;
    let bytes = artifact
        .get(wiring.modules.get(module).cloned().ok_or_else(missing)?)
        .ok_or_else(|| TotalityError::Undecodable("module range out of bounds".into()))?;
    let parsed = Module::parse(bytes)?;
    let entry = parsed.export_named(export).ok_or_else(missing)?;
    let shim = parsed.shim_closure(&wiring.abi_support(module))?;
    let undischarged = wiring.undischarged_imports(artifact, instance, &parsed.imports);
    parsed.walk(entry, &shim, &undischarged)
}

/// One core function, as the component's index space names it.
#[derive(Clone)]
struct CoreFuncRef {
    /// The core instance it is aliased out of.
    instance: u32,
    /// The name that instance exports it under.
    name: String,
}

/// A core function, by what defines it.
#[derive(Clone)]
enum CoreFunc {
    /// Aliased out of a core instance's export, so it has a body.
    Alias(CoreFuncRef),
    /// Defined by a `canon lower` over the component function at this
    /// index, so calling it leaves the guest for the host.
    Lowered(u32),
    /// A `resource.drop` over the type at this component type index:
    /// calling it runs the resource's destructor.
    Drop(u32),
    /// A canon builtin with neither a body nor a component function
    /// behind it.
    Opaque,
}

/// A component function, by what defines it.
#[derive(Clone)]
enum ComponentFunc {
    /// Defined by a `canon lift` over the core function at this index.
    Lifted(u32),
    /// Aliased out of an imported instance's export: the host function
    /// itself, under the interface that declares it.
    Imported {
        /// The component instance index the alias reads from.
        instance: u32,
        /// The name that instance exports it under.
        name: String,
    },
    /// Anything else the index space counts.
    Opaque,
}

/// A core instance, by what defines it.
enum CoreInstance {
    /// Instantiated from a module, with the arguments each of its import
    /// groups was satisfied by.
    Module {
        /// The module index.
        module: u32,
        /// Import-group name to the core instance satisfying it.
        args: Vec<(String, u32)>,
    },
    /// A synthetic bag of exports, naming core functions and core tables
    /// directly.
    Exports {
        /// Exported functions, by the core function index each names.
        funcs: Vec<(String, u32)>,
        /// Exported tables, by the core table index each names.
        tables: Vec<(String, u32)>,
    },
}

/// A component's wiring, as one walk over its payloads.
///
/// Four index spaces, each read in the order the payloads define it,
/// because every lookup below is an index into one of them and a
/// miscount would silently resolve to the wrong function. Built once and
/// asked twice: which body an exported method runs, and which bodies the
/// canonical ABI designates as its own support.
struct Wiring {
    /// Each core module's byte range, in definition order.
    modules: Vec<Range<usize>>,
    /// Each core instance, by what defines it.
    instances: Vec<CoreInstance>,
    /// The core function index space.
    core_funcs: Vec<CoreFunc>,
    /// The component function index space.
    component_funcs: Vec<ComponentFunc>,
    /// Imported instances' names, in the component instance index space.
    ///
    /// Which interface a host function belongs to is read from here
    /// rather than from any name the guest chose: a core module names
    /// its import groups whatever it likes, and a scan that trusted
    /// those names would let a package call the arithmetic under the
    /// spelling of a state accessor.
    import_instances: Vec<String>,
    /// Exported function names, by component function index.
    exports: Vec<(String, u32)>,
    /// Core function indices a lift designates as realloc or post-return.
    designated: BTreeSet<u32>,
    /// The core table index space: which instance's export each aliased
    /// table is, which is what proves a fixups module's segments land in
    /// the shim's table rather than one that merely shares a name.
    core_tables: Vec<(u32, String)>,
    /// The component type index space, holding `(interface, name)` where
    /// a slot is an imported instance's type export — which is how a
    /// kernel resource reaches a `resource.drop` — and `None` everywhere
    /// else. Every slot is counted even when nothing is recorded for it,
    /// because a drop names its resource by index and a miscount would
    /// silently resolve to the wrong one.
    types: Vec<Option<(String, String)>>,
}

impl Wiring {
    #[allow(clippy::too_many_lines)] // one walk over the payloads that define the index spaces
    fn read(artifact: &[u8]) -> Result<Self, TotalityError> {
        let mut wiring = Self {
            modules: Vec::new(),
            instances: Vec::new(),
            core_funcs: Vec::new(),
            component_funcs: Vec::new(),
            import_instances: Vec::new(),
            exports: Vec::new(),
            designated: BTreeSet::new(),
            core_tables: Vec::new(),
            types: Vec::new(),
        };
        let fail = |e: BinaryReaderError| TotalityError::Undecodable(e.to_string());

        for payload in Parser::new(0).parse_all(artifact) {
            match payload.map_err(fail)? {
                Payload::ModuleSection {
                    unchecked_range, ..
                } => wiring.modules.push(unchecked_range),
                Payload::InstanceSection(reader) => {
                    for instance in reader {
                        wiring.instances.push(match instance.map_err(fail)? {
                            Instance::Instantiate { module_index, args } => CoreInstance::Module {
                                module: module_index,
                                args: args
                                    .iter()
                                    .filter(|arg| arg.kind == InstantiationArgKind::Instance)
                                    .map(|arg| (arg.name.to_owned(), arg.index))
                                    .collect(),
                            },
                            Instance::FromExports(exports) => CoreInstance::Exports {
                                funcs: exports
                                    .iter()
                                    .filter(|export| export.kind == ExternalKind::Func)
                                    .map(|export| (export.name.to_owned(), export.index))
                                    .collect(),
                                tables: exports
                                    .iter()
                                    .filter(|export| export.kind == ExternalKind::Table)
                                    .map(|export| (export.name.to_owned(), export.index))
                                    .collect(),
                            },
                        });
                    }
                }
                Payload::ComponentTypeSection(reader) => {
                    // Declared types name no imported resource; each
                    // still takes its slot in the type index space.
                    for entry in reader {
                        entry.map_err(fail)?;
                        wiring.types.push(None);
                    }
                }
                Payload::ComponentImportSection(reader) => {
                    for import in reader {
                        // Each kind appends to its own index space, so
                        // all three are tracked: a function import counts
                        // against the component function space, an
                        // instance import is what an alias later names
                        // its interface through, and a type import takes
                        // a type slot.
                        let import = import.map_err(fail)?;
                        match import.ty {
                            ComponentTypeRef::Func(_) => {
                                wiring.component_funcs.push(ComponentFunc::Opaque);
                            }
                            ComponentTypeRef::Instance(_) => {
                                wiring.import_instances.push(import.name.name.to_owned());
                            }
                            ComponentTypeRef::Type(_) => wiring.types.push(None),
                            _ => {}
                        }
                    }
                }
                Payload::ComponentAliasSection(reader) => {
                    for alias in reader {
                        match alias.map_err(fail)? {
                            ComponentAlias::CoreInstanceExport {
                                kind: ExternalKind::Func,
                                instance_index,
                                name,
                            } => wiring.core_funcs.push(CoreFunc::Alias(CoreFuncRef {
                                instance: instance_index,
                                name: name.to_owned(),
                            })),
                            ComponentAlias::CoreInstanceExport {
                                kind: ExternalKind::Table,
                                instance_index,
                                name,
                            } => wiring.core_tables.push((instance_index, name.to_owned())),
                            ComponentAlias::InstanceExport {
                                kind: ComponentExternalKind::Func,
                                instance_index,
                                name,
                            } => wiring.component_funcs.push(ComponentFunc::Imported {
                                instance: instance_index,
                                name: name.to_owned(),
                            }),
                            // An aliased type export is how a kernel
                            // resource reaches a `resource.drop`: the
                            // interface is the imported instance's, never
                            // a name the guest chose.
                            ComponentAlias::InstanceExport {
                                kind: ComponentExternalKind::Type,
                                instance_index,
                                name,
                            } => {
                                let interface = usize::try_from(instance_index)
                                    .ok()
                                    .and_then(|index| wiring.import_instances.get(index))
                                    .map(|full| {
                                        full.rsplit_once('/')
                                            .map_or(full.as_str(), |(_, tail)| tail)
                                            .to_owned()
                                    });
                                wiring.types.push(interface.map(|i| (i, name.to_owned())));
                            }
                            ComponentAlias::Outer {
                                kind: ComponentOuterAliasKind::Type,
                                ..
                            } => wiring.types.push(None),
                            _ => {}
                        }
                    }
                }
                Payload::ComponentCanonicalSection(reader) => {
                    for function in reader {
                        // Every canon form but `lift` defines a core
                        // function, and `lift` defines a component one.
                        // Matching the exclusion keeps both spaces aligned
                        // even for a form this profile does not admit.
                        match function.map_err(fail)? {
                            CanonicalFunction::Lift {
                                core_func_index,
                                options,
                                ..
                            } => {
                                wiring
                                    .component_funcs
                                    .push(ComponentFunc::Lifted(core_func_index));
                                for option in &options {
                                    if let CanonicalOption::Realloc(index)
                                    | CanonicalOption::PostReturn(index) = option
                                    {
                                        wiring.designated.insert(*index);
                                    }
                                }
                            }
                            CanonicalFunction::Lower { func_index, .. } => {
                                wiring.core_funcs.push(CoreFunc::Lowered(func_index));
                            }
                            CanonicalFunction::ResourceDrop { resource } => {
                                wiring.core_funcs.push(CoreFunc::Drop(resource));
                            }
                            _ => wiring.core_funcs.push(CoreFunc::Opaque),
                        }
                    }
                }
                Payload::ComponentExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(fail)?;
                        // A re-exported type takes a new slot aliasing
                        // what it exports, on the same terms as the
                        // function re-exports below.
                        if export.kind == ComponentExternalKind::Type {
                            let aliased = usize::try_from(export.index)
                                .ok()
                                .and_then(|index| wiring.types.get(index).cloned())
                                .flatten();
                            wiring.types.push(aliased);
                        }
                        if export.kind != ComponentExternalKind::Func {
                            continue;
                        }
                        wiring
                            .exports
                            .push((export.name.name.to_owned(), export.index));
                        // An export defines an index of its own, aliasing
                        // what it exports; carrying the lift through keeps
                        // a later reference to it resolvable.
                        let aliased = usize::try_from(export.index)
                            .ok()
                            .and_then(|index| wiring.component_funcs.get(index).cloned())
                            .unwrap_or(ComponentFunc::Opaque);
                        wiring.component_funcs.push(aliased);
                    }
                }
                _ => {}
            }
        }
        Ok(wiring)
    }

    /// The core function `index` names: the instance it is aliased out
    /// of, the module that instance runs, and the export name.
    fn core_func(&self, index: u32) -> Option<(u32, usize, &str)> {
        let slot = usize::try_from(index).ok()?;
        let CoreFunc::Alias(reference) = self.core_funcs.get(slot)? else {
            return None;
        };
        let instance = usize::try_from(reference.instance).ok()?;
        let CoreInstance::Module { module, .. } = self.instances.get(instance)? else {
            return None;
        };
        Some((
            reference.instance,
            usize::try_from(*module).ok()?,
            &reference.name,
        ))
    }

    /// The body an exported method runs: the instance it runs in, its
    /// module, and the name that module exports it under.
    fn entry(&self, method: &str) -> Option<(u32, usize, &str)> {
        let (_, index) = self.exports.iter().find(|(name, _)| name == method)?;
        let slot = usize::try_from(*index).ok()?;
        let ComponentFunc::Lifted(lifted) = self.component_funcs.get(slot)? else {
            return None;
        };
        self.core_func(*lifted)
    }

    /// Whether the core function at `core` is one a total body may call:
    /// a lowering of a [`DISCHARGED`] host function, a
    /// [`DISCHARGED_DROPS`] resource's drop, or a shim trampoline that
    /// resolves to one of those.
    fn discharged_core(&self, artifact: &[u8], core: u32) -> bool {
        let dropped = |index: u32| -> Option<(&str, &str)> {
            let (interface, name) = usize::try_from(index)
                .ok()
                .and_then(|slot| self.types.get(slot))?
                .as_ref()?;
            Some((interface.as_str(), name.as_str()))
        };
        match usize::try_from(core)
            .ok()
            .and_then(|i| self.core_funcs.get(i))
        {
            Some(CoreFunc::Lowered(_)) => self
                .host_function(core)
                .is_some_and(|resolved| DISCHARGED.contains(&resolved)),
            Some(CoreFunc::Drop(resource)) => {
                dropped(*resource).is_some_and(|resolved| DISCHARGED_DROPS.contains(&resolved))
            }
            // A lowering that needs canon options is routed through a
            // shim: this alias is its trampoline, and the verdict is the
            // one the slot it calls through resolves to. The target is a
            // lowering or a drop, never a further trampoline, so the
            // recursion is one level deep by construction.
            Some(CoreFunc::Alias(reference)) => self
                .trampoline_target(artifact, reference.instance, &reference.name)
                .is_some_and(|target| {
                    !matches!(
                        usize::try_from(target)
                            .ok()
                            .and_then(|i| self.core_funcs.get(i)),
                        Some(CoreFunc::Alias(_))
                    ) && self.discharged_core(artifact, target)
                }),
            _ => false,
        }
    }

    /// The core function a shim trampoline reaches, resolved through the
    /// wiring and never through a name: the trampoline's body names a
    /// table slot, a fixups module's element segment fills that slot from
    /// its own imports, and the instantiation arguments say what those
    /// imports are.
    ///
    /// `None` where the shape does not hold — a body that is not a
    /// single `call_indirect` over a constant slot, a slot no segment
    /// fills, or two segments filling it with different functions.
    fn trampoline_target(&self, artifact: &[u8], instance: u32, name: &str) -> Option<u32> {
        let module_bytes = |module: u32| {
            usize::try_from(module)
                .ok()
                .and_then(|index| self.modules.get(index).cloned())
                .and_then(|range| artifact.get(range))
        };
        let CoreInstance::Module { module, .. } = usize::try_from(instance)
            .ok()
            .and_then(|i| self.instances.get(i))?
        else {
            return None;
        };
        let shim = Module::parse(module_bytes(*module)?).ok()?;
        let slot = shim.trampoline_slot(shim.export_named(name)?)?;

        let mut resolved: Option<u32> = None;
        for candidate in &self.instances {
            let CoreInstance::Module { module, args } = candidate else {
                continue;
            };
            let Ok(fixups) = Module::parse(match module_bytes(*module) {
                Some(bytes) => bytes,
                None => continue,
            }) else {
                continue;
            };
            // The fixups module writes into a table it imports; the
            // wiring must say that table is the shim instance's own.
            let Some((group, field)) = &fixups.table_import else {
                continue;
            };
            let Some(supplied) = args.iter().find(|(name, _)| name == group).map(|a| a.1) else {
                continue;
            };
            let Some(CoreInstance::Exports { tables, .. }) = usize::try_from(supplied)
                .ok()
                .and_then(|i| self.instances.get(i))
            else {
                continue;
            };
            let Some(table) = tables.iter().find(|(name, _)| name == field).map(|t| t.1) else {
                continue;
            };
            let owned_by_shim = usize::try_from(table)
                .ok()
                .and_then(|index| self.core_tables.get(index))
                .is_some_and(|(source, _)| *source == instance);
            if !owned_by_shim {
                continue;
            }
            for (offset, items) in &fixups.elements {
                let Some(at) = slot.checked_sub(*offset) else {
                    continue;
                };
                let Some(function) = usize::try_from(at).ok().and_then(|at| items.get(at)) else {
                    continue;
                };
                // The filled function must be one the fixups module
                // imports, so the instantiation arguments resolve it.
                let Some((group, field)) = usize::try_from(*function)
                    .ok()
                    .and_then(|index| fixups.imports.get(index))
                else {
                    continue;
                };
                let Some(supplied) = args.iter().find(|(name, _)| name == group).map(|a| a.1)
                else {
                    continue;
                };
                let Some(CoreInstance::Exports { funcs, .. }) = usize::try_from(supplied)
                    .ok()
                    .and_then(|i| self.instances.get(i))
                else {
                    continue;
                };
                let Some(core) = funcs.iter().find(|(name, _)| name == field).map(|f| f.1) else {
                    continue;
                };
                // Two fills of one slot would race at instantiation;
                // nothing so shaped is resolvable.
                if resolved.is_some_and(|earlier| earlier != core) {
                    return None;
                }
                resolved = Some(core);
            }
        }
        resolved
    }

    /// The interface and function name a core function index reaches, for
    /// a core function that lowers an imported host function.
    fn host_function(&self, core: u32) -> Option<(&str, &str)> {
        let slot = usize::try_from(core).ok()?;
        let CoreFunc::Lowered(component) = self.core_funcs.get(slot)? else {
            return None;
        };
        let slot = usize::try_from(*component).ok()?;
        let ComponentFunc::Imported { instance, name } = self.component_funcs.get(slot)? else {
            return None;
        };
        let interface = self
            .import_instances
            .get(usize::try_from(*instance).ok()?)?
            .as_str();
        Some((
            interface
                .rsplit_once('/')
                .map_or(interface, |(_, tail)| tail),
            name,
        ))
    }

    /// The import indices of `imports` that no declaration discharges, as
    /// the core module's own function space numbers them.
    ///
    /// The chain is the component's, not the guest's: a module's import
    /// group name resolves through the instantiation argument to a core
    /// instance, that instance's export to a lowered core function, and
    /// the lowering to the imported interface function it stands for. A
    /// package can name its import group anything at all and reach the
    /// same verdict.
    ///
    /// The judgment is an allowlist: an import is discharged only where
    /// the whole chain resolves to a [`DISCHARGED`] host function or a
    /// [`DISCHARGED_DROPS`] resource's drop — directly, or through the
    /// shim a lowering that needs canon options is routed by. One that
    /// resolves to anything else — a refusable state op, the faulting
    /// arithmetic, another module's ordinary body — is refused, along
    /// with one that resolves to nothing at all: what cannot be
    /// identified cannot be discharged.
    fn undischarged_imports(
        &self,
        artifact: &[u8],
        instance: u32,
        imports: &[(String, String)],
    ) -> BTreeSet<u32> {
        let discharged = |group: &str, field: &str| -> Option<bool> {
            let Some(CoreInstance::Module { args, .. }) = usize::try_from(instance)
                .ok()
                .and_then(|i| self.instances.get(i))
            else {
                return Some(false);
            };
            let supplied = args.iter().find(|(name, _)| name == group)?.1;
            let Some(CoreInstance::Exports { funcs, .. }) = usize::try_from(supplied)
                .ok()
                .and_then(|i| self.instances.get(i))
            else {
                return Some(false);
            };
            let core = funcs.iter().find(|(name, _)| name == field)?.1;
            Some(self.discharged_core(artifact, core))
        };
        imports
            .iter()
            .enumerate()
            .filter_map(|(index, (group, field))| {
                (!discharged(group, field).unwrap_or(false))
                    .then(|| u32::try_from(index).ok())
                    .flatten()
            })
            .collect()
    }

    /// The names `module` exports that a lift designates as canonical-ABI
    /// support: its realloc and its post-return.
    ///
    /// Read from the component's own wiring rather than from a naming
    /// convention, and that is the whole point. A prefix is something an
    /// author picks, so excluding everything called `cabi_*` lets a
    /// package export its panicking helper under that name and have the
    /// scan look away. What a lift designates is not a name but a role:
    /// the runtime calls this function to allocate, on every value that
    /// crosses the boundary. A package can still point that role at a
    /// body of its own — but then that body must actually serve as the
    /// allocator, which leaves it with the same gap the honest allocator
    /// already has rather than a new one.
    ///
    /// Scoped to one module, because that is where the walk will look the
    /// names up: a realloc designated out of some other instance is not
    /// this module's function however it is named.
    fn abi_support(&self, module: usize) -> BTreeSet<String> {
        self.designated
            .iter()
            .filter_map(|index| self.core_func(*index))
            .filter(|(_, designated, _)| *designated == module)
            .map(|(_, _, name)| name.to_owned())
            .collect()
    }
}

/// A core module's function space, indexed the way calls index it.
struct Module<'a> {
    /// Imported functions, as `(group, field)`, in index order: function
    /// `i` of this list is core function index `i`, and imports occupy
    /// the low indices with no body here.
    imports: Vec<(String, String)>,
    bodies: Vec<FunctionBody<'a>>,
    /// Exported function indices by name, for finding the shim's roots.
    exports: Vec<(&'a str, u32)>,
    /// The imported table, as `(group, field)` — the profile admits one
    /// table per module, so there is at most one, and it is what a fixups
    /// module's element segments land in.
    table_import: Option<(String, String)>,
    /// Element segments, as `(offset, function indices)`; the profile
    /// admits only active, constant-offset, function-indexed segments.
    elements: Vec<(u32, Vec<u32>)>,
}

impl<'a> Module<'a> {
    fn parse(module: &'a [u8]) -> Result<Self, TotalityError> {
        let mut parsed = Self {
            imports: Vec::new(),
            bodies: Vec::new(),
            exports: Vec::new(),
            table_import: None,
            elements: Vec::new(),
        };
        let fail = |e: BinaryReaderError| TotalityError::Undecodable(e.to_string());
        for payload in Parser::new(0).parse_all(module) {
            match payload.map_err(fail)? {
                Payload::ImportSection(reader) => {
                    // Grouped in the compact encoding, so flatten before
                    // counting: what shifts the defined functions' indices
                    // is the number of imports, not of groups.
                    for import in reader.into_imports() {
                        let import = import.map_err(fail)?;
                        match import.ty {
                            TypeRef::Func(_) => parsed
                                .imports
                                .push((import.module.to_owned(), import.name.to_owned())),
                            TypeRef::Table(_) if parsed.table_import.is_none() => {
                                parsed.table_import =
                                    Some((import.module.to_owned(), import.name.to_owned()));
                            }
                            _ => {}
                        }
                    }
                }
                Payload::ElementSection(reader) => {
                    for element in reader {
                        let element = element.map_err(fail)?;
                        let ElementKind::Active { offset_expr, .. } = &element.kind else {
                            continue;
                        };
                        let Some(offset) = const_offset(offset_expr) else {
                            continue;
                        };
                        let ElementItems::Functions(functions) = &element.items else {
                            continue;
                        };
                        let items: Vec<u32> = functions
                            .clone()
                            .into_iter()
                            .collect::<Result<_, _>>()
                            .map_err(fail)?;
                        parsed.elements.push((offset, items));
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export =
                            export.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
                        if matches!(export.kind, ExternalKind::Func) {
                            parsed.exports.push((export.name, export.index));
                        }
                    }
                }
                Payload::CodeSectionEntry(body) => parsed.bodies.push(body),
                _ => {}
            }
        }
        Ok(parsed)
    }

    /// Defined function `i` sits at `imports + i`; anything below that is
    /// an import, which has no body here to walk into.
    fn body_of(&self, index: u32) -> Option<&FunctionBody<'a>> {
        index
            .checked_sub(u32::try_from(self.imports.len()).ok()?)
            .and_then(|defined| self.bodies.get(defined as usize))
    }

    fn callees(&self, index: u32) -> Result<Vec<u32>, TotalityError> {
        let Some(body) = self.body_of(index) else {
            return Ok(Vec::new());
        };
        let reader = body
            .get_operators_reader()
            .map_err(|e| TotalityError::Undecodable(e.to_string()))?;
        let mut out = Vec::new();
        for op in reader {
            let op = op.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
            if let Operator::Call { function_index } = op {
                out.push(function_index);
            }
        }
        Ok(out)
    }

    fn export_named(&self, name: &str) -> Option<u32> {
        self.exports
            .iter()
            .find(|(export, _)| *export == name)
            .map(|(_, index)| *index)
    }

    /// The constant table slot the body at `index` calls through — the
    /// shim-trampoline shape, read off the operators: exactly one
    /// `call_indirect`, its slot pushed by the constant before it.
    fn trampoline_slot(&self, index: u32) -> Option<u32> {
        let reader = self.body_of(index)?.get_operators_reader().ok()?;
        let mut slot: Option<u32> = None;
        let mut previous: Option<Operator<'_>> = None;
        for op in reader {
            let op = op.ok()?;
            if matches!(op, Operator::CallIndirect { .. }) {
                let Some(Operator::I32Const { value }) = previous else {
                    return None;
                };
                if slot.replace(value.cast_unsigned()).is_some() {
                    return None;
                }
            }
            previous = Some(op);
        }
        slot
    }

    /// Everything the designated ABI support reaches.
    fn shim_closure(&self, designated: &BTreeSet<String>) -> Result<BTreeSet<u32>, TotalityError> {
        let frontier: Vec<u32> = self
            .exports
            .iter()
            .filter(|(name, _)| designated.contains(*name))
            .map(|(_, index)| *index)
            .collect();
        self.reachable(frontier, &BTreeSet::new())
    }

    /// Indices reachable from `frontier`, not descending into `excluded`.
    fn reachable(
        &self,
        mut frontier: Vec<u32>,
        excluded: &BTreeSet<u32>,
    ) -> Result<BTreeSet<u32>, TotalityError> {
        let mut seen = BTreeSet::new();
        while let Some(index) = frontier.pop() {
            if excluded.contains(&index) || !seen.insert(index) {
                continue;
            }
            frontier.extend(self.callees(index)?);
        }
        Ok(seen)
    }

    /// Check every body reachable from `entry` that is not shim, and
    /// refuse where the reachable set calls an import nothing discharges.
    fn walk(
        &self,
        entry: u32,
        shim: &BTreeSet<u32>,
        undischarged: &BTreeSet<u32>,
    ) -> Result<(), TotalityError> {
        let reached = self.reachable(vec![entry], shim)?;
        if let Some(called) = reached.iter().find(|index| undischarged.contains(index)) {
            let named = usize::try_from(*called)
                .ok()
                .and_then(|index| self.imports.get(index))
                .map_or_else(
                    || called.to_string(),
                    |(group, field)| format!("{group}/{field}"),
                );
            return Err(TotalityError::FaultingHostCall(named));
        }
        for index in reached {
            if let Some(body) = self.body_of(index) {
                check_body(body)?;
            }
        }
        Ok(())
    }
}

/// A segment offset's constant value, or `None` for anything richer —
/// which the profile refuses at deploy, so an unresolvable offset here
/// only leaves the trampoline undischarged.
fn const_offset(expr: &ConstExpr<'_>) -> Option<u32> {
    let mut reader = expr.get_operators_reader();
    let Ok(Operator::I32Const { value }) = reader.read() else {
        return None;
    };
    matches!(reader.read(), Ok(Operator::End)).then(|| value.cast_unsigned())
}

/// Whether the operator that pushed the divisor proves it non-zero.
const fn divisor_is_non_zero(previous: Option<&Operator<'_>>) -> bool {
    match previous {
        Some(Operator::I32Const { value }) => *value != 0,
        Some(Operator::I64Const { value }) => *value != 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use wat::parse_str;

    use super::*;

    /// Compile one function body to a core module and check it.
    fn check(body: &str) -> Result<(), TotalityError> {
        let wat = format!("(module (func $f {body}))");
        let bytes = parse_str(&wat).expect("valid wat");
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::CodeSectionEntry(body) = payload.expect("parses") {
                return check_body(&body);
            }
        }
        panic!("a module with a function has a code section");
    }

    #[test]
    fn arithmetic_that_cannot_fault_passes() {
        assert_eq!(check("i32.const 2 i32.const 3 i32.add drop"), Ok(()));
    }

    /// The one that matters: every Rust panic lands here, so its absence
    /// is what the whole check leans on.
    #[test]
    fn unreachable_is_refused() {
        assert_eq!(check("unreachable"), Err(TotalityError::Unreachable));
    }

    /// A constant divisor is provably non-zero and a computed one is not,
    /// which is the whole of the peephole.
    #[test]
    fn division_is_refused_unless_the_divisor_is_a_non_zero_literal() {
        assert_eq!(check("i32.const 6 i32.const 3 i32.div_s drop"), Ok(()));
        assert_eq!(
            check("i32.const 6 i32.const 0 i32.div_s drop"),
            Err(TotalityError::DivisionByUnprovenDivisor),
        );
        assert_eq!(
            check("i32.const 6 local.get 0 i32.div_s drop"),
            Err(TotalityError::DivisionByUnprovenDivisor),
        );
    }

    #[test]
    fn a_loop_is_refused_for_having_no_fuel_ceiling() {
        assert_eq!(check("loop end"), Err(TotalityError::UnboundedLoop),);
    }

    /// A branch is not a loop: forward control flow terminates, so it
    /// carries a static fuel bound and stays admissible.
    #[test]
    fn forward_branching_is_admitted() {
        assert_eq!(check("block br 0 end"), Ok(()));
        assert_eq!(check("i32.const 1 if else end"), Ok(()));
    }

    /// Two functions, the second reached from the first by a direct call.
    fn caller_and_callee(callee_body: &str) -> Vec<u8> {
        parse_str(format!(
            "(module (func $entry call $callee) (func $callee {callee_body}))"
        ))
        .expect("valid wat")
    }

    /// The mark speaks for the transitive body: a caller whose own
    /// operators are harmless still cannot be total when what it calls
    /// can panic.
    #[test]
    fn a_callee_that_can_fault_denies_its_caller() {
        assert_eq!(check_reachable(&caller_and_callee("nop"), 0), Ok(()));
        assert_eq!(
            check_reachable(&caller_and_callee("unreachable"), 0),
            Err(TotalityError::Unreachable),
        );
    }

    /// Reachability is the whole of it: a faulting function nobody calls
    /// says nothing about the entry, which is what lets one package hold
    /// both a total method and a fallible one.
    #[test]
    fn an_unreached_faulting_function_is_not_the_entrys_problem() {
        let module =
            parse_str("(module (func $entry nop) (func $orphan unreachable))").expect("valid wat");
        assert_eq!(check_reachable(&module, 0), Ok(()));
        assert_eq!(
            check_reachable(&module, 1),
            Err(TotalityError::Unreachable),
            "the orphan is refused on its own account, just not the entry's",
        );
    }

    /// Recursion terminates the walk rather than hanging it. The cycle is
    /// refused for its loop-free-but-unbounded fuel elsewhere; what this
    /// pins is that the visit set closes.
    #[test]
    fn a_call_cycle_terminates_the_walk() {
        let module = parse_str("(module (func $a call 1) (func $b call 0))").expect("valid wat");
        assert_eq!(check_reachable(&module, 0), Ok(()));
    }

    /// A bare core module designates nothing, so nothing is set aside:
    /// with no component around it there is no `canon lift` to name a
    /// realloc, and a faulting callee is the entry's problem however it
    /// is named.
    #[test]
    fn a_name_alone_sets_nothing_aside() {
        for export in ["helper", "cabi_realloc"] {
            let module = parse_str(format!(
                r#"(module
                     (func $entry call $helper)
                     (func $helper unreachable)
                     (export "deposit" (func $entry))
                     (export "{export}" (func $helper)))"#
            ))
            .expect("valid wat");
            assert_eq!(
                check_reachable(&module, 0),
                Err(TotalityError::Unreachable),
                "exporting the faulting body as {export:?} must not excuse it",
            );
        }
    }

    /// The method's body is the one its export lifts, not the one that
    /// happens to share its name.
    ///
    /// A core module names its exports whatever it likes, and only the
    /// component's wiring says which of them an exported method runs. A
    /// scan that matched on the name would read the decoy here and grant
    /// the mark to the body beside it — which is the hole the ABI support
    /// set refuses to open, shut on the same terms.
    #[test]
    fn a_core_export_that_merely_shares_the_methods_name_is_not_its_body() {
        let component = parse_str(
            r#"(component
                 (core module $m
                   (func $lifted unreachable)
                   (func $decoy nop)
                   (export "lifted" (func $lifted))
                   (export "deposit" (func $decoy)))
                 (core instance $i (instantiate $m))
                 (func (export "deposit") (canon lift (core func $i "lifted"))))"#,
        )
        .expect("valid wat");
        assert_eq!(
            check_method(&component, "deposit"),
            Err(TotalityError::Unreachable),
            "the mark is judged against the body the export lifts",
        );

        // The same wiring over a body that cannot fault admits, so the
        // refusal above is the code and not the shape.
        let sound = parse_str(
            r#"(component
                 (core module $m
                   (func $lifted nop)
                   (export "lifted" (func $lifted)))
                 (core instance $i (instantiate $m))
                 (func (export "deposit") (canon lift (core func $i "lifted"))))"#,
        )
        .expect("valid wat");
        assert_eq!(check_method(&sound, "deposit"), Ok(()));
    }

    /// A method the component does not export has no body to judge, and
    /// a core module exporting the name is not the component doing so.
    #[test]
    fn a_method_the_component_does_not_export_is_refused() {
        let component = parse_str(
            r#"(component
                 (core module $m
                   (func $f nop)
                   (export "deposit" (func $f)))
                 (core instance $i (instantiate $m)))"#,
        )
        .expect("valid wat");
        assert_eq!(
            check_method(&component, "deposit"),
            Err(TotalityError::NoSuchExport("deposit".to_string())),
        );
    }

    /// The realloc a lift designates is set aside in the module it lives
    /// in, and a body of the same name elsewhere is not it.
    ///
    /// Two modules, each exporting a panicking `alloc`; only one is wired
    /// to the lift as its realloc. The method sits in the other, so its
    /// own `alloc` is an ordinary callee and denies the mark.
    #[test]
    fn the_designation_is_scoped_to_the_module_that_holds_it() {
        let component = parse_str(
            r#"(component
                 (core module $glue
                   (func $alloc (param i32 i32 i32 i32) (result i32) unreachable)
                   (memory (export "mem") 1 1)
                   (export "alloc" (func $alloc)))
                 (core module $main
                   (func $body call $alloc)
                   (func $alloc unreachable)
                   (export "body" (func $body))
                   (export "alloc" (func $alloc)))
                 (core instance $g (instantiate $glue))
                 (core instance $m (instantiate $main))
                 (func (export "deposit") (param "v" (list u8))
                   (canon lift (core func $m "body")
                     (memory $g "mem") (realloc (func $g "alloc")))))"#,
        )
        .expect("valid wat");
        assert_eq!(
            check_method(&component, "deposit"),
            Err(TotalityError::Unreachable),
            "the designated realloc is the glue module's, not the main module's",
        );
    }

    /// A bare module's import call is refused: with no component wiring
    /// to say which host function it reaches, nothing can discharge it —
    /// however the guest spelled the import.
    #[test]
    fn a_bare_modules_import_call_is_refused() {
        let module = parse_str(
            r#"(module (import "hyperscale:kernel/env" "clock" (func)) (func $entry call 0))"#,
        )
        .expect("valid wat");
        // The import occupies index 0, so the defined entry is index 1 —
        // the shift the walk has to get right to find any body at all.
        assert_eq!(
            check_reachable(&module, 1),
            Err(TotalityError::FaultingHostCall(
                "hyperscale:kernel/env/clock".to_string()
            )),
        );
        // And one nobody calls is not the entry's problem: the verdict is
        // about the reachable set, not the import section.
        let unreached =
            parse_str(r#"(module (import "k" "f" (func)) (func $entry nop))"#).expect("valid wat");
        assert_eq!(check_reachable(&unreached, 1), Ok(()));
    }

    /// A component importing `math`, lowering `mul-div` and
    /// `geometric-mean`, with one method per import and the group named
    /// by the caller.
    fn math_caller(group: &str, call: &str) -> Vec<u8> {
        parse_str(format!(
            r#"(component
                 (import "hyperscale:kernel/math" (instance $math
                   (type (record (field "limb0" u64) (field "limb1" u64)
                                 (field "limb2" u64) (field "limb3" u64)))
                   (export "wide" (type (eq 0)))
                   (type (enum "down" "up"))
                   (export "rounding" (type (eq 2)))
                   (export "mul-div" (func (param "a" 1) (param "b" 1) (param "c" 1)
                                           (param "r" 3) (result 1)))
                   (export "geometric-mean" (func (param "a" 1) (param "b" 1) (result 1)))))
                 (alias export $math "mul-div" (func $md))
                 (alias export $math "geometric-mean" (func $gm))
                 (core module $alloc (memory (export "mem") 1 1))
                 (core instance $a (instantiate $alloc))
                 (core func $md_l (canon lower (func $md) (memory $a "mem")))
                 (core func $gm_l (canon lower (func $gm) (memory $a "mem")))
                 (core module $m
                   (import "env" "mem" (memory 1 1))
                   (import "{group}" "md" (func $md
                     (param i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32 i32)))
                   (import "{group}" "gm" (func $gm
                     (param i64 i64 i64 i64 i64 i64 i64 i64 i32)))
                   (func (export "run") {call}))
                 (core instance $i (instantiate $m
                   (with "env" (instance $a))
                   (with "{group}" (instance
                     (export "md" (func $md_l))
                     (export "gm" (func $gm_l))))))
                 (func (export "deposit") (canon lift (core func $i "run"))))"#
        ))
        .expect("valid wat")
    }

    const MUL_DIV_CALL: &str = "(call $md (i64.const 1) (i64.const 0) (i64.const 0) (i64.const 0) \
        (i64.const 1) (i64.const 0) (i64.const 0) (i64.const 0) \
        (i64.const 1) (i64.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 0))";

    const GEOMETRIC_MEAN_CALL: &str = "(call $gm (i64.const 4) (i64.const 0) (i64.const 0) \
        (i64.const 0) (i64.const 1) (i64.const 0) (i64.const 0) (i64.const 0) (i32.const 0))";

    /// The blanket admission of host calls rests on a total leg running
    /// with its handles already materialized, so the gate that would
    /// refuse is discharged before the body starts. Nothing discharges a
    /// zero divisor, so the arithmetic that can meet one is refused.
    #[test]
    fn a_faulting_host_call_denies_the_mark() {
        assert_eq!(
            check_method(&math_caller("k", MUL_DIV_CALL), "deposit"),
            Err(TotalityError::FaultingHostCall("k/md".to_string())),
        );
    }

    /// And the one that cannot fault is admitted, which is the whole
    /// reason the rule names functions rather than the interface: a
    /// square root has no refusal to discharge.
    #[test]
    fn a_total_host_call_keeps_the_mark() {
        assert_eq!(
            check_method(&math_caller("k", GEOMETRIC_MEAN_CALL), "deposit"),
            Ok(()),
        );
    }

    /// A state operation that can refuse is outside the allowlist: what a
    /// take refuses — an insufficient balance — is a runtime value no
    /// declaration discharges, so a body that can meet it cannot be
    /// total.
    #[test]
    fn a_refusable_state_op_denies_the_mark() {
        let component = parse_str(
            r#"(component
                 (import "hyperscale:kernel/state" (instance $state
                   (export "bucket" (type $bk (sub resource)))
                   (type $amt_decl (record (field "low" u64) (field "high" u64)))
                   (export "amount" (type $amt (eq $amt_decl)))
                   (export "bucket-take" (func (param "b" (borrow $bk)) (param "amount" $amt)
                                               (result (own $bk))))))
                 (alias export $state "bucket-take" (func $take))
                 (core module $alloc (memory (export "mem") 1 1))
                 (core instance $a (instantiate $alloc))
                 (core func $take_l (canon lower (func $take) (memory $a "mem")))
                 (core module $m
                   (import "k" "take" (func $take (param i32 i64 i64) (result i32)))
                   (func (export "run")
                     (call $take (i32.const 0) (i64.const 1) (i64.const 0)) drop))
                 (core instance $i (instantiate $m
                   (with "k" (instance (export "take" (func $take_l))))))
                 (func (export "deposit") (canon lift (core func $i "run"))))"#,
        )
        .expect("valid wat");
        assert_eq!(
            check_method(&component, "deposit"),
            Err(TotalityError::FaultingHostCall("k/take".to_string())),
        );
    }

    /// The verdict is read off the component's wiring, never off a name
    /// the guest chose: a package that calls the arithmetic through an
    /// import group spelled like a state accessor reaches the same
    /// refusal, because what resolves it is the lowering.
    #[test]
    fn an_import_group_named_to_deceive_is_refused_all_the_same() {
        assert_eq!(
            check_method(
                &math_caller("hyperscale:kernel/state", MUL_DIV_CALL),
                "deposit"
            ),
            Err(TotalityError::FaultingHostCall(
                "hyperscale:kernel/state/md".to_string()
            )),
        );
    }
}
