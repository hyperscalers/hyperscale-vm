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
//! One chain stands at a time. Every import is a host function that
//! returns to the frame that called it without re-entering the guest, so
//! the walk terminates on imports and the reserve covers the host frames
//! at either end of the chain.
//!
//! `call_indirect` resolves to the table entries whose signature matches
//! the call site — an over-approximation, but a type-directed one: ignoring
//! types inflates the account guest's back edges from 15 to 47 and rejects
//! artifacts that are perfectly sound.

use std::collections::{BTreeMap, BTreeSet};

use wasmparser::{
    CompositeInnerType, ElementItems, FuncValidatorAllocations, Operator, Parser, Payload, TypeRef,
    ValType, ValidPayload, Validator,
};

use crate::profile;
use crate::validator::{ProfileError, profile_features};

/// A core function signature, compared structurally.
type FuncSig = (Vec<ValType>, Vec<ValType>);

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

/// Everything the two passes collect about a module.
#[derive(Default)]
struct ModuleFacts {
    /// Signature per type index.
    types: Vec<FuncSig>,
    /// Type index per function, imports first.
    func_types: Vec<u32>,
    /// How many functions the module imports: the low indices, each a
    /// host frame the walk terminates on.
    imported_funcs: usize,
    /// Element segments, as the function indices they place.
    elements: Vec<Vec<u32>>,
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

    /// A function index as a local one, or `None` for an import.
    const fn local(&self, func: u32) -> Option<usize> {
        (func as usize).checked_sub(self.imported_funcs)
    }
}

/// Proves a module cannot exhaust the native stack.
///
/// # Errors
///
/// [`ProfileError::Structural`] for a frame past the per-function bound, a
/// cyclic call graph, or a chain that does not fit either budget.
pub fn check_stack_bounds(bytes: &[u8]) -> Result<(), ProfileError> {
    let facts = collect(bytes)?;
    for (local, func) in facts.funcs.iter().enumerate() {
        if func.slots > profile::MAX_SLOTS_PER_FRAME {
            return Err(ProfileError::Structural(format!(
                "function {local} needs {} value slots, over the {} the frame bound allows",
                func.slots,
                profile::MAX_SLOTS_PER_FRAME
            )));
        }
    }

    let (edges, cost) = call_graph(&facts);
    let heaviest = heaviest_path(&edges, &cost)?;
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

/// The native bytes one frame of `slots` value slots costs under the
/// profile's model.
const fn frame_bytes(slots: usize) -> usize {
    profile::STACK_FRAME_OVERHEAD_BYTES + slots * profile::STACK_BYTES_PER_SLOT
}

/// What the module's table holds once every element segment has been
/// applied, indexed by signature alone.
///
/// Offsets are dropped: a table holds the union of every segment written
/// into it. That widens the edge set — a call site reaches entries no
/// offset would put under it — so it can only refuse an artifact a
/// precise walk admits, never the reverse, and resolving offsets would
/// mean modelling every index a `call_indirect` can compute at run time
/// anyway.
fn table(facts: &ModuleFacts) -> Vec<(FuncSig, u32)> {
    facts
        .elements
        .iter()
        .flatten()
        .filter_map(|func| facts.signature(*func).map(|sig| (sig.clone(), *func)))
        .collect()
}

/// The call graph over the module's local functions: the edges, and each
/// node's cost.
#[allow(clippy::type_complexity)] // two maps over one node type, read once
fn call_graph(facts: &ModuleFacts) -> (BTreeMap<usize, BTreeSet<usize>>, BTreeMap<usize, Cost>) {
    let table = table(facts);
    let mut edges: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    let mut cost: BTreeMap<usize, Cost> = BTreeMap::new();
    for (local, func) in facts.funcs.iter().enumerate() {
        cost.insert(
            local,
            Cost {
                bytes: frame_bytes(func.slots),
                frames: 1,
            },
        );
        let targets = edges.entry(local).or_default();
        // An import is a host frame the chain ends on, so only a local
        // callee is an edge.
        targets.extend(
            func.callees
                .iter()
                .filter_map(|callee| facts.local(*callee)),
        );
        for ty in &func.indirect {
            let Some(signature) = facts.types.get(*ty as usize) else {
                continue;
            };
            targets.extend(
                table
                    .iter()
                    .filter(|(entry, _)| entry == signature)
                    .filter_map(|(_, target)| facts.local(*target)),
            );
        }
    }
    (edges, cost)
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
    graph: &BTreeMap<usize, BTreeSet<usize>>,
    cost: &BTreeMap<usize, Cost>,
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
    let mut marks: BTreeMap<usize, Mark> = BTreeMap::new();
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

/// Two passes: the structural one for types, imports, and edges, then a
/// validator-driven one for the deepest operand stack per function.
fn collect(bytes: &[u8]) -> Result<ModuleFacts, ProfileError> {
    let mut facts = collect_structure(bytes)?;
    collect_frames(bytes, &mut facts)?;
    Ok(facts)
}

/// Types, imports, and the table's element segments.
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
                    if let TypeRef::Func(ty) | TypeRef::FuncExact(ty) = import.ty {
                        facts.imported_funcs += 1;
                        facts.func_types.push(ty);
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    local_types.push(ty.map_err(|e| ProfileError::Feature(e.to_string()))?);
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
                    // against the module's table, which the profile's
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
