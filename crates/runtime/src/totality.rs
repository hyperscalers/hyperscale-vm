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
//! There is no third. WIT has `result<t, e>`, and no world in this
//! protocol uses it: every export returns a value or nothing, and a
//! method declines by trapping. So the error arm a signature could carry
//! is not a signal that distinguishes anything here, and the scan is not
//! half the answer but nearly all of it.
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
    ComponentTypeRef, ExternalKind, FunctionBody, Instance, InstantiationArgKind, Operator, Parser,
    Payload, TypeRef,
};

/// The `math` functions whose only failure is a deterministic abort.
///
/// A total method may not call one. The blanket admission of host calls
/// below rests on a total leg running with every handle already
/// materialized from its declared effect set, so the gate that would
/// refuse has been discharged before the body starts — and nothing
/// discharges these, because what they refuse is a divisor or a width,
/// both of them runtime values no declaration speaks about.
///
/// `geometric-mean` is deliberately absent: it is total on every input,
/// so a body that calls it is no less total for having done so.
const FAULTING_MATH: &[&str] = &["mul-div", "fraction-compose", "fraction-cmp", "fixed-pow"];

/// The interface those functions belong to, as an import name's suffix.
const MATH_INTERFACE: &str = "math";

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
/// **A call to a state import is admitted, and that is the kernel's
/// promise rather than the scan's finding.** Host calls are how a body
/// reaches the kernel at all, and they can refuse — but a total leg runs
/// with every handle already materialized from its declared effect set,
/// so the gate that would refuse has been discharged before the body
/// starts. The scan cannot see that and does not try to; it records here
/// that the guarantee comes from the boundary, so a change to how handles
/// are materialized is a change to what this check means.
///
/// That promise reaches exactly as far as the declaration does, which is
/// why it does not cover all of `math`. What `mul-div` refuses is a zero
/// divisor or a width, both runtime values no effect set speaks about, so
/// no gate discharges them and the call can fault inside a body that is
/// otherwise total. Those functions are named in [`FAULTING_MATH`] and
/// refused here; `geometric-mean` is total on every input and stays
/// admitted. Resolving which import a call reaches is the component's
/// wiring to answer, never a name the guest picked — see
/// [`Wiring::faulting_imports`].
///
/// `entry` indexes the module's whole function space — imports first,
/// then defined functions — the same space [`Operator::Call`] uses.
///
/// Nothing is set aside. A bare core module has no canonical section, so
/// there is no lift to designate a realloc and no name alone can stand in
/// for one; the glue exclusion belongs to [`check_method`], which has a
/// component's wiring to read it from.
///
/// # Errors
///
/// The first [`TotalityError`] any reachable body yields, or
/// [`TotalityError::Undecodable`] if the module does not parse.
pub fn check_reachable(module: &[u8], entry: u32) -> Result<(), TotalityError> {
    let parsed = Module::parse(module)?;
    parsed.walk(entry, &BTreeSet::new(), &BTreeSet::new())
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
    let faulting = wiring.faulting_imports(instance, &parsed.imports);
    parsed.walk(entry, &shim, &faulting)
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
    /// A synthetic bag of exports, naming core functions directly.
    Exports(Vec<(String, u32)>),
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
                            Instance::FromExports(exports) => CoreInstance::Exports(
                                exports
                                    .iter()
                                    .filter(|export| export.kind == ExternalKind::Func)
                                    .map(|export| (export.name.to_owned(), export.index))
                                    .collect(),
                            ),
                        });
                    }
                }
                Payload::ComponentImportSection(reader) => {
                    for import in reader {
                        // Each kind appends to its own index space, so
                        // both are tracked: a function import counts
                        // against the component function space, and an
                        // instance import is what an alias later names
                        // its interface through.
                        let import = import.map_err(fail)?;
                        match import.ty {
                            ComponentTypeRef::Func(_) => {
                                wiring.component_funcs.push(ComponentFunc::Opaque);
                            }
                            ComponentTypeRef::Instance(_) => {
                                wiring.import_instances.push(import.name.name.to_owned());
                            }
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
                            ComponentAlias::InstanceExport {
                                kind: ComponentExternalKind::Func,
                                instance_index,
                                name,
                            } => wiring.component_funcs.push(ComponentFunc::Imported {
                                instance: instance_index,
                                name: name.to_owned(),
                            }),
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
                            _ => wiring.core_funcs.push(CoreFunc::Opaque),
                        }
                    }
                }
                Payload::ComponentExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(fail)?;
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

    /// The import indices of `imports` that reach a host function which
    /// can fault, as the core module's own function space numbers them.
    ///
    /// The chain is the component's, not the guest's: a module's import
    /// group name resolves through the instantiation argument to a core
    /// instance, that instance's export to a lowered core function, and
    /// the lowering to the imported interface function it stands for. A
    /// package can name its import group anything at all and reach the
    /// same verdict.
    fn faulting_imports(&self, instance: u32, imports: &[(String, String)]) -> BTreeSet<u32> {
        let Some(CoreInstance::Module { args, .. }) = usize::try_from(instance)
            .ok()
            .and_then(|i| self.instances.get(i))
        else {
            return BTreeSet::new();
        };
        imports
            .iter()
            .enumerate()
            .filter_map(|(index, (group, field))| {
                let supplied = args.iter().find(|(name, _)| name == group)?.1;
                let CoreInstance::Exports(exports) = usize::try_from(supplied)
                    .ok()
                    .and_then(|i| self.instances.get(i))?
                else {
                    return None;
                };
                let core = exports.iter().find(|(name, _)| name == field)?.1;
                let (interface, function) = self.host_function(core)?;
                (interface == MATH_INTERFACE && FAULTING_MATH.contains(&function))
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
}

impl<'a> Module<'a> {
    fn parse(module: &'a [u8]) -> Result<Self, TotalityError> {
        let mut parsed = Self {
            imports: Vec::new(),
            bodies: Vec::new(),
            exports: Vec::new(),
        };
        for payload in Parser::new(0).parse_all(module) {
            match payload.map_err(|e| TotalityError::Undecodable(e.to_string()))? {
                Payload::ImportSection(reader) => {
                    // Grouped in the compact encoding, so flatten before
                    // counting: what shifts the defined functions' indices
                    // is the number of imports, not of groups.
                    for import in reader.into_imports() {
                        let import =
                            import.map_err(|e| TotalityError::Undecodable(e.to_string()))?;
                        if matches!(import.ty, TypeRef::Func(_)) {
                            parsed
                                .imports
                                .push((import.module.to_owned(), import.name.to_owned()));
                        }
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
    /// refuse where the reachable set calls a host function that faults.
    fn walk(
        &self,
        entry: u32,
        shim: &BTreeSet<u32>,
        faulting: &BTreeSet<u32>,
    ) -> Result<(), TotalityError> {
        let reached = self.reachable(vec![entry], shim)?;
        if let Some(called) = reached.iter().find(|index| faulting.contains(index)) {
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

    /// An imported function has no body to walk into, and a call to one
    /// is admitted on the kernel's precondition discharge rather than on
    /// anything the scan established.
    #[test]
    fn a_call_into_an_import_is_admitted() {
        let module = parse_str(r#"(module (import "k" "f" (func)) (func $entry call 0))"#)
            .expect("valid wat");
        // The import occupies index 0, so the defined entry is index 1 —
        // the shift the walk has to get right to find any body at all.
        assert_eq!(check_reachable(&module, 1), Ok(()));
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
