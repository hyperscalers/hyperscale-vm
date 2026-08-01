//! Deploy-time stack bounds.
//!
//! Native stack consumption is the one resource the profile cannot meter
//! at runtime without instrumenting the guest: the engine has no wasm-level
//! call-depth counter, so where it exhausts depends on the host ISA and on
//! codegen, while the executable spec counts frames. Matching the two trap
//! points is not achievable; making the trap unreachable is.
//!
//! So the bound is proven at deploy. Each function's frame is modelled from
//! its slot count ([`profile::STACK_BYTES_PER_SLOT`], measured by
//! `spike_frame_size`), the call graph is required to be acyclic, and the
//! heaviest path through it must fit the budget.
//!
//! Two budgets, not one. Stack bytes are what the blessed engine exhausts,
//! and frames are what the executable spec counts; a chain fits only if it
//! meets both, and the deepest chain need not be the heaviest one. The
//! frame cap ([`profile::MAX_CALL_CHAIN_FRAMES`]) is what keeps the spec's
//! counter out of reach — the byte budget alone admits chains well past
//! it — so an artifact that passes cannot exhaust the stack in either
//! runtime, and the divergence has no reachable witness.
//!
//! The graph spans the whole component, not one core module at a time. A
//! module's imports are wired to other modules' exports by the component's
//! core instantiations, and an element segment in one module populates a
//! table another module calls through — the shim-and-fixups shape
//! `wit-bindgen` emits. Judging modules separately would weigh every edge
//! across those seams at zero and, worse, would not see a call cycle that
//! crosses one: core instantiation is acyclic, but a fixups module filling
//! an earlier instance's table with a later instance's export closes a
//! cycle at run time that no single module contains.
//!
//! `call_indirect` resolves to the table entries whose signature matches
//! the call site — an over-approximation, but a type-directed one: ignoring
//! types inflates the account guest's back edges from 15 to 47 and rejects
//! artifacts that are perfectly sound. Signatures are compared
//! structurally, because two modules number their types independently.

use std::collections::{BTreeMap, BTreeSet};

use wasmparser::{
    CanonicalFunction, ComponentAlias, CompositeInnerType, ElementItems, ExternalKind,
    FuncValidatorAllocations, Instance as InstanceReader, InstantiationArgKind, Operator, Parser,
    Payload, TypeRef, ValType, ValidPayload, Validator,
};

use crate::profile;
use crate::validator::{ProfileError, profile_features};

/// A core function signature, compared structurally.
type FuncSig = (Vec<ValType>, Vec<ValType>);

/// A table in the linked graph. An instance that imports a table shares the
/// identity of the one that declared it, which is how an element segment in
/// one module reaches another module's call sites.
type TableId = usize;

/// One node of the linked call graph: a core instance, and a function among
/// the functions its module defines.
type Node = (usize, usize);

/// Where a call lands.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FuncRef {
    /// A canon-defined function: a host frame at the canonical-ABI
    /// boundary, covered by the reserve rather than by this walk.
    Host,
    /// A wasm function, by instance and index among its module's own.
    Wasm(usize, usize),
}

/// What an import asks for. Globals and tags are refused by the structural
/// pass, so nothing here has to model them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportKind {
    Func,
    Table,
    Other,
}

/// One import, as the linker resolves it.
struct ImportRef {
    module: String,
    name: String,
    kind: ImportKind,
}

/// What the bound needs to know about one local function.
#[derive(Default)]
struct FuncFacts {
    /// Parameters, declared locals, and the deepest operand stack.
    slots: usize,
    /// Directly called functions, by index in the module's function space.
    callees: BTreeSet<u32>,
    /// Type indices reached through `call_indirect`.
    indirect: BTreeSet<u32>,
}

/// Everything the two passes collect about a core module.
#[derive(Default)]
struct ModuleFacts {
    /// Signature per type index.
    types: Vec<FuncSig>,
    /// Type index per function, imports first.
    func_types: Vec<u32>,
    /// Imports in declaration order.
    imports: Vec<ImportRef>,
    imported_funcs: usize,
    /// Whether the module declares its own table rather than importing one.
    declares_table: bool,
    /// Element segments, as the function indices they place.
    elements: Vec<Vec<u32>>,
    /// Exports, in declaration order.
    exports: Vec<(String, ExternalKind, u32)>,
    /// One entry per local function, in code-section order.
    funcs: Vec<FuncFacts>,
}

impl ModuleFacts {
    /// The signature of a function by its index in the module's function
    /// space, imports first.
    fn signature(&self, func: u32) -> Option<&FuncSig> {
        self.func_types
            .get(func as usize)
            .and_then(|ty| self.types.get(*ty as usize))
    }
}

/// A core function as the component's index space names it.
enum CoreFuncSlot {
    /// Canon-defined: a host frame.
    Canon,
    /// An alias of an earlier core instance's export.
    Alias { instance: u32, name: String },
}

/// A core instance before its imports are resolved.
enum InstanceDef {
    Instantiate {
        module: u32,
        args: Vec<(String, u32)>,
    },
    Exports(Vec<(String, ExternalKind, u32)>),
}

/// A resolved core-instance export. Memories carry no call edges.
#[derive(Clone, Copy)]
enum Export {
    Func(FuncRef),
    Table(TableId),
}

/// One resolved core instance.
#[derive(Default)]
struct CoreInstance {
    /// The module it instantiates; `None` for a synthetic export bag.
    module: Option<usize>,
    /// The full function index space: imports resolved, then local functions.
    funcs: Vec<FuncRef>,
    /// The table it calls through, declared or imported.
    table: Option<TableId>,
    exports: BTreeMap<String, Export>,
}

/// The modelled native frame of a function with `slots` value slots.
const fn frame_bytes(slots: usize) -> usize {
    profile::STACK_FRAME_OVERHEAD_BYTES + profile::STACK_BYTES_PER_SLOT * slots
}

/// Proves a bare core module cannot exhaust the native stack.
///
/// A module judged on its own is the one-instance case of the linked graph:
/// every import is a host frame, because there is no other module for one
/// to resolve to.
///
/// # Errors
///
/// [`ProfileError::Structural`] for a frame past the per-function bound, a
/// cyclic call graph, or a chain that does not fit either budget.
pub fn check_stack_bounds(bytes: &[u8]) -> Result<(), ProfileError> {
    let facts = collect(bytes)?;
    let instance = bare_instance(0, &facts, 0, &mut 0);
    check_linked(&[facts], &[instance])
}

/// A module judged on its own: every import is a host frame, because there
/// is no wiring for one to resolve to, and its element segments land in a
/// table nothing else can see.
fn bare_instance(
    module: usize,
    facts: &ModuleFacts,
    instance: usize,
    next_table: &mut TableId,
) -> CoreInstance {
    let mut funcs = vec![FuncRef::Host; facts.imported_funcs];
    funcs.extend((0..facts.funcs.len()).map(|local| FuncRef::Wasm(instance, local)));
    *next_table += 1;
    CoreInstance {
        module: Some(module),
        funcs,
        table: Some(*next_table - 1),
        exports: BTreeMap::new(),
    }
}

/// Proves a component cannot exhaust the native stack, over the graph its
/// core instantiations link together.
///
/// # Errors
///
/// Exactly [`check_stack_bounds`]'s, plus a core instantiation outside the
/// contract shape.
pub fn check_component_stack_bounds(bytes: &[u8]) -> Result<(), ProfileError> {
    let (modules, instances) = link(bytes)?;
    check_linked(&modules, &instances)
}

/// The stack bound over a linked instance graph.
fn check_linked(modules: &[ModuleFacts], instances: &[CoreInstance]) -> Result<(), ProfileError> {
    for facts in modules {
        for (local, func) in facts.funcs.iter().enumerate() {
            if func.slots > profile::MAX_SLOTS_PER_FRAME {
                return Err(ProfileError::Structural(format!(
                    "function {local} needs {} value slots, over the {} the frame bound allows",
                    func.slots,
                    profile::MAX_SLOTS_PER_FRAME
                )));
            }
        }
    }

    let tables = populate_tables(modules, instances);
    let (graph, cost) = call_graph(modules, instances, &tables);

    let heaviest = heaviest_path(&graph, &cost)?;
    if heaviest.bytes > profile::MAX_CALL_CHAIN_BYTES {
        return Err(ProfileError::Structural(format!(
            "the heaviest call chain needs {} stack bytes, over the {} the profile \
             reserves for one chain",
            heaviest.bytes,
            profile::MAX_CALL_CHAIN_BYTES
        )));
    }
    if heaviest.frames > profile::MAX_CALL_CHAIN_FRAMES {
        return Err(ProfileError::Structural(format!(
            "the deepest call chain stands {} frames, over the {} the profile admits",
            heaviest.frames,
            profile::MAX_CALL_CHAIN_FRAMES
        )));
    }
    Ok(())
}

/// What every table holds once every instance's element segments have been
/// applied. A segment resolves its function indices in the index space of
/// the instance that carries it, and writes into whichever table that
/// instance uses — its own, or one it imported from an earlier instance.
///
/// Offsets are dropped: a table holds the union of every segment written
/// into it, indexed by signature alone. That widens the edge set — a call
/// site reaches entries no offset would put under it — so it can only
/// refuse an artifact a precise walk admits, never the reverse, and
/// resolving offsets would mean modelling every index a `call_indirect`
/// can compute at run time anyway.
fn populate_tables(
    modules: &[ModuleFacts],
    instances: &[CoreInstance],
) -> BTreeMap<TableId, Vec<(FuncSig, FuncRef)>> {
    let mut tables: BTreeMap<TableId, Vec<(FuncSig, FuncRef)>> = BTreeMap::new();
    for instance in instances {
        let (Some(module), Some(table)) = (instance.module, instance.table) else {
            continue;
        };
        let Some(facts) = modules.get(module) else {
            continue;
        };
        for segment in &facts.elements {
            for func in segment {
                let (Some(target), Some(signature)) =
                    (instance.funcs.get(*func as usize), facts.signature(*func))
                else {
                    continue;
                };
                tables
                    .entry(table)
                    .or_default()
                    .push((signature.clone(), *target));
            }
        }
    }
    tables
}

/// The linked call graph and each node's cost.
fn call_graph(
    modules: &[ModuleFacts],
    instances: &[CoreInstance],
    tables: &BTreeMap<TableId, Vec<(FuncSig, FuncRef)>>,
) -> (BTreeMap<Node, BTreeSet<Node>>, BTreeMap<Node, Cost>) {
    let mut graph: BTreeMap<Node, BTreeSet<Node>> = BTreeMap::new();
    let mut cost: BTreeMap<Node, Cost> = BTreeMap::new();
    for (index, instance) in instances.iter().enumerate() {
        let Some(facts) = instance.module.and_then(|module| modules.get(module)) else {
            continue;
        };
        for (local, func) in facts.funcs.iter().enumerate() {
            let node = (index, local);
            cost.insert(
                node,
                Cost {
                    bytes: frame_bytes(func.slots),
                    frames: 1,
                },
            );
            let edges = graph.entry(node).or_default();
            for callee in &func.callees {
                if let Some(FuncRef::Wasm(target, local)) = instance.funcs.get(*callee as usize) {
                    edges.insert((*target, *local));
                }
            }
            for ty in &func.indirect {
                let (Some(signature), Some(table)) =
                    (facts.types.get(*ty as usize), instance.table)
                else {
                    continue;
                };
                for (entry, target) in tables.get(&table).into_iter().flatten() {
                    if entry == signature
                        && let FuncRef::Wasm(target, local) = target
                    {
                        edges.insert((*target, *local));
                    }
                }
            }
        }
    }
    (graph, cost)
}

/// What one call chain costs, in the two currencies the profile budgets.
#[derive(Clone, Copy, Default)]
struct Cost {
    bytes: usize,
    frames: usize,
}

impl Cost {
    /// This node's own cost on top of the heaviest chain below it.
    const fn over(self, below: Self) -> Self {
        Self {
            bytes: self.bytes + below.bytes,
            frames: self.frames + below.frames,
        }
    }

    /// The componentwise maximum. The two budgets are taken independently
    /// because the deepest chain and the heaviest one need not be the same
    /// chain, and a chain has to fit both.
    fn worst(self, other: Self) -> Self {
        Self {
            bytes: self.bytes.max(other.bytes),
            frames: self.frames.max(other.frames),
        }
    }
}

/// The heaviest root-to-leaf path, rejecting cycles.
fn heaviest_path(
    graph: &BTreeMap<Node, BTreeSet<Node>>,
    cost: &BTreeMap<Node, Cost>,
) -> Result<Cost, ProfileError> {
    /// Visit state: on the current path, or finished.
    enum Mark {
        Open,
        Done(Cost),
    }

    let cyclic = || {
        ProfileError::Structural(
            "the call graph is cyclic, so no static stack bound exists".to_string(),
        )
    };
    let mut marks: BTreeMap<Node, Mark> = BTreeMap::new();
    let mut heaviest = Cost::default();
    // Iterative post-order so a deep graph cannot exhaust our own stack.
    for &root in graph.keys() {
        if marks.contains_key(&root) {
            continue;
        }
        let mut stack = vec![(root, false)];
        while let Some((node, expanded)) = stack.pop() {
            if expanded {
                let below = graph
                    .get(&node)
                    .into_iter()
                    .flatten()
                    .map(|next| match marks.get(next) {
                        Some(Mark::Done(cost)) => *cost,
                        _ => Cost::default(),
                    })
                    .fold(Cost::default(), Cost::worst);
                let total = cost.get(&node).copied().unwrap_or_default().over(below);
                marks.insert(node, Mark::Done(total));
                heaviest = heaviest.worst(total);
                continue;
            }
            match marks.get(&node) {
                Some(Mark::Done(_)) => continue,
                Some(Mark::Open) => return Err(cyclic()),
                None => {}
            }
            marks.insert(node, Mark::Open);
            stack.push((node, true));
            for next in graph.get(&node).into_iter().flatten() {
                match marks.get(next) {
                    Some(Mark::Done(_)) => {}
                    Some(Mark::Open) => return Err(cyclic()),
                    None => stack.push((*next, false)),
                }
            }
        }
    }
    Ok(heaviest)
}

/// Reads the component's core modules and the instantiations that wire
/// them, resolving each instance's imports against the ones before it.
fn link(bytes: &[u8]) -> Result<(Vec<ModuleFacts>, Vec<CoreInstance>), ProfileError> {
    let mut modules: Vec<ModuleFacts> = Vec::new();
    let mut core_funcs: Vec<CoreFuncSlot> = Vec::new();
    let mut core_tables: Vec<(u32, String)> = Vec::new();
    let mut defs: Vec<InstanceDef> = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| ProfileError::Feature(e.to_string()))?;
        match payload {
            Payload::ModuleSection {
                unchecked_range, ..
            } => modules.push(collect(&bytes[unchecked_range])?),
            Payload::ComponentCanonicalSection(reader) => {
                for canon in reader {
                    // Every canon form but `lift` defines a core function,
                    // and `lift` defines a component one. Matching the
                    // exclusion rather than the inclusions keeps the index
                    // space aligned even for a form this profile does not
                    // admit — a miscount here would silently misresolve
                    // every alias after it.
                    let canon = canon.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if !matches!(canon, CanonicalFunction::Lift { .. }) {
                        core_funcs.push(CoreFuncSlot::Canon);
                    }
                }
            }
            Payload::ComponentAliasSection(reader) => {
                for alias in reader {
                    let alias = alias.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if let ComponentAlias::CoreInstanceExport {
                        kind,
                        instance_index,
                        name,
                    } = alias
                    {
                        match kind {
                            ExternalKind::Func => core_funcs.push(CoreFuncSlot::Alias {
                                instance: instance_index,
                                name: name.to_string(),
                            }),
                            ExternalKind::Table => {
                                core_tables.push((instance_index, name.to_string()));
                            }
                            _ => {}
                        }
                    }
                }
            }
            Payload::InstanceSection(reader) => {
                for instance in reader {
                    let instance = instance.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    defs.push(instance_def(&instance)?);
                }
            }
            _ => {}
        }
    }

    let mut resolved: Vec<CoreInstance> = Vec::new();
    let mut next_table: TableId = 0;
    let mut instantiated: BTreeSet<usize> = BTreeSet::new();
    for def in &defs {
        let instance = match def {
            InstanceDef::Exports(list) => export_bag(list, &core_funcs, &core_tables, &resolved),
            InstanceDef::Instantiate { module, args } => {
                instantiated.insert(*module as usize);
                instantiate(*module, args, &modules, &resolved, &mut next_table)?
            }
        };
        resolved.push(instance);
    }

    // A module the component never instantiates cannot run, so nothing
    // requires bounding it — but it is bounded anyway, as a bare module.
    // The alternative is a check that silently covers the wired-up part of
    // an artifact and calls that the artifact.
    for (module, facts) in modules.iter().enumerate() {
        if !instantiated.contains(&module) {
            let instance = bare_instance(module, facts, resolved.len(), &mut next_table);
            resolved.push(instance);
        }
    }
    Ok((modules, resolved))
}

fn instance_def(instance: &InstanceReader<'_>) -> Result<InstanceDef, ProfileError> {
    match instance {
        InstanceReader::Instantiate { module_index, args } => {
            let mut resolved = Vec::with_capacity(args.len());
            for arg in &**args {
                if arg.kind != InstantiationArgKind::Instance {
                    return Err(ProfileError::Structural(
                        "only instance arguments instantiate a core module".to_string(),
                    ));
                }
                resolved.push((arg.name.to_string(), arg.index));
            }
            Ok(InstanceDef::Instantiate {
                module: *module_index,
                args: resolved,
            })
        }
        InstanceReader::FromExports(exports) => Ok(InstanceDef::Exports(
            exports
                .iter()
                .map(|export| (export.name.to_string(), export.kind, export.index))
                .collect(),
        )),
    }
}

/// A synthetic instance that only names items defined elsewhere.
fn export_bag(
    list: &[(String, ExternalKind, u32)],
    core_funcs: &[CoreFuncSlot],
    core_tables: &[(u32, String)],
    resolved: &[CoreInstance],
) -> CoreInstance {
    let mut exports = BTreeMap::new();
    for (name, kind, index) in list {
        let item = match kind {
            ExternalKind::Func => core_func(core_funcs, resolved, *index).map(Export::Func),
            ExternalKind::Table => {
                core_tables
                    .get(*index as usize)
                    .and_then(|(instance, export)| {
                        match resolved.get(*instance as usize)?.exports.get(export)? {
                            Export::Table(table) => Some(Export::Table(*table)),
                            Export::Func(_) => None,
                        }
                    })
            }
            _ => None,
        };
        if let Some(item) = item {
            exports.insert(name.clone(), item);
        }
    }
    CoreInstance {
        exports,
        ..CoreInstance::default()
    }
}

/// One core function of the component's index space.
fn core_func(
    core_funcs: &[CoreFuncSlot],
    resolved: &[CoreInstance],
    index: u32,
) -> Option<FuncRef> {
    match core_funcs.get(index as usize)? {
        CoreFuncSlot::Canon => Some(FuncRef::Host),
        CoreFuncSlot::Alias { instance, name } => {
            match resolved.get(*instance as usize)?.exports.get(name)? {
                Export::Func(target) => Some(*target),
                Export::Table(_) => None,
            }
        }
    }
}

/// Instantiates a core module: imports resolve against earlier instances,
/// local functions take fresh nodes, and the table is the declared one or
/// the imported one.
fn instantiate(
    module: u32,
    args: &[(String, u32)],
    modules: &[ModuleFacts],
    resolved: &[CoreInstance],
    next_table: &mut TableId,
) -> Result<CoreInstance, ProfileError> {
    let facts = modules.get(module as usize).ok_or_else(|| {
        ProfileError::Structural("core instance names an undefined module".to_string())
    })?;
    let index = resolved.len();
    let mut funcs = Vec::with_capacity(facts.func_types.len());
    let mut imported_table = None;
    for import in &facts.imports {
        let supplied = args
            .iter()
            .find(|(name, _)| *name == import.module)
            .and_then(|(_, instance)| resolved.get(*instance as usize))
            .and_then(|instance| instance.exports.get(&import.name));
        match (import.kind, supplied) {
            (ImportKind::Func, Some(Export::Func(target))) => funcs.push(*target),
            // An import the wiring does not satisfy is a host frame rather
            // than a refusal: component validation has already rejected a
            // genuinely missing one, and treating it as unresolved would
            // weigh a real edge at zero.
            (ImportKind::Func, _) => funcs.push(FuncRef::Host),
            (ImportKind::Table, Some(Export::Table(table))) => imported_table = Some(*table),
            _ => {}
        }
    }
    funcs.extend((0..facts.funcs.len()).map(|local| FuncRef::Wasm(index, local)));

    let table = if facts.declares_table {
        *next_table += 1;
        Some(*next_table - 1)
    } else {
        imported_table
    };

    let mut exports = BTreeMap::new();
    for (name, kind, item) in &facts.exports {
        let export = match kind {
            ExternalKind::Func => funcs.get(*item as usize).copied().map(Export::Func),
            ExternalKind::Table => table.map(Export::Table),
            _ => None,
        };
        if let Some(export) = export {
            exports.insert(name.clone(), export);
        }
    }

    Ok(CoreInstance {
        module: Some(module as usize),
        funcs,
        table,
        exports,
    })
}

/// Two passes: the structural one for types, imports, and edges, then a
/// validator-driven one for the deepest operand stack per function.
fn collect(bytes: &[u8]) -> Result<ModuleFacts, ProfileError> {
    let mut facts = collect_structure(bytes)?;
    collect_frames(bytes, &mut facts)?;
    Ok(facts)
}

/// Types, imports, exports, and the table's element segments.
fn collect_structure(bytes: &[u8]) -> Result<ModuleFacts, ProfileError> {
    let mut facts = ModuleFacts::default();
    let mut local_types: Vec<u32> = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| ProfileError::Feature(e.to_string()))?;
        match payload {
            Payload::TypeSection(reader) => {
                for group in reader {
                    let group = group.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    for sub in group.types() {
                        facts.types.push(match &sub.composite_type.inner {
                            CompositeInnerType::Func(f) => {
                                (f.params().to_vec(), f.results().to_vec())
                            }
                            _ => (Vec::new(), Vec::new()),
                        });
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    let kind = match import.ty {
                        TypeRef::Func(ty) => {
                            facts.imported_funcs += 1;
                            facts.func_types.push(ty);
                            ImportKind::Func
                        }
                        TypeRef::Table(_) => ImportKind::Table,
                        _ => ImportKind::Other,
                    };
                    facts.imports.push(ImportRef {
                        module: import.module.to_string(),
                        name: import.name.to_string(),
                        kind,
                    });
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    local_types.push(ty.map_err(|e| ProfileError::Feature(e.to_string()))?);
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    table.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    facts.declares_table = true;
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    facts
                        .exports
                        .push((export.name.to_string(), export.kind, export.index));
                }
            }
            Payload::ElementSection(reader) => {
                for element in reader {
                    let element = element.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if let ElementItems::Functions(items) = element.items {
                        let mut segment = Vec::new();
                        for func in items {
                            segment.push(func.map_err(|e| ProfileError::Feature(e.to_string()))?);
                        }
                        facts.elements.push(segment);
                    }
                }
            }
            _ => {}
        }
    }
    facts.func_types.extend(local_types);
    Ok(facts)
}

/// Slot counts and call edges, driven through the validator so the deepest
/// operand stack comes from the same machinery that type-checks the body.
fn collect_frames(bytes: &[u8], facts: &mut ModuleFacts) -> Result<(), ProfileError> {
    let mut validator = Validator::new_with_features(profile_features());
    let mut allocs = FuncValidatorAllocations::default();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| ProfileError::Feature(e.to_string()))?;
        let valid = validator
            .payload(&payload)
            .map_err(|e| ProfileError::Feature(e.to_string()))?;
        if let ValidPayload::Func(to_validate, body) = valid {
            let mut func = to_validate.into_validator(allocs);
            let locals = body
                .get_locals_reader()
                .map_err(|e| ProfileError::Feature(e.to_string()))?;
            let offset = locals.original_position();
            for entry in locals {
                let (count, ty) = entry.map_err(|e| ProfileError::Feature(e.to_string()))?;
                func.define_locals(offset, count, ty)
                    .map_err(|e| ProfileError::Feature(e.to_string()))?;
            }
            let index = facts.imported_funcs + facts.funcs.len();
            let params = u32::try_from(index)
                .ok()
                .and_then(|index| facts.signature(index))
                .map_or(0, |(params, _)| params.len());
            let mut record = FuncFacts {
                slots: params + func.len_locals() as usize,
                ..FuncFacts::default()
            };
            let base = record.slots;
            let mut reader = body
                .get_operators_reader()
                .map_err(|e| ProfileError::Feature(e.to_string()))?;
            while !reader.eof() {
                let position = reader.original_position();
                let op = reader
                    .read()
                    .map_err(|e| ProfileError::Feature(e.to_string()))?;
                match op {
                    Operator::Call { function_index } => {
                        record.callees.insert(function_index);
                    }
                    // The table a call site names is dropped along with the
                    // index it computes: every indirect call is weighed
                    // against the instance's table, which the profile's
                    // one-table limit makes exact today and an
                    // over-approximation if that limit ever rises.
                    Operator::CallIndirect { type_index, .. } => {
                        record.indirect.insert(type_index);
                    }
                    _ => {}
                }
                func.op(position, &op)
                    .map_err(|e| ProfileError::Feature(e.to_string()))?;
                record.slots = record
                    .slots
                    .max(base + func.operand_stack_height() as usize);
            }
            allocs = func.into_allocations();
            facts.funcs.push(record);
        }
    }
    Ok(())
}
