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
//! `spike_frame_size`), the intra-module call graph is required to be
//! acyclic, and the heaviest path through it must fit the budget.
//!
//! Two budgets, not one. Stack bytes are what the blessed engine exhausts,
//! and frames are what the executable spec counts; a chain fits only if it
//! meets both, and the deepest chain need not be the heaviest one. The
//! frame cap ([`profile::MAX_CALL_CHAIN_FRAMES`]) is what keeps the spec's
//! counter out of reach — the byte budget alone admits chains well past
//! it — so an artifact that passes cannot exhaust the stack in either
//! runtime, and the divergence has no reachable witness.
//!
//! `call_indirect` resolves to the element-segment functions whose type
//! matches the call site — an over-approximation, but a type-directed one:
//! ignoring types inflates the account guest's back edges from 15 to 47 and
//! rejects artifacts that are perfectly sound.

use std::collections::{BTreeMap, BTreeSet};

use wasmparser::{
    CompositeInnerType, ElementItems, FuncValidatorAllocations, Operator, Parser, Payload, TypeRef,
    ValidPayload, Validator,
};

use crate::profile;
use crate::validator::{ProfileError, profile_features};

/// What the bound needs to know about one local function.
#[derive(Default)]
struct FuncFacts {
    /// Parameters, declared locals, and the deepest operand stack.
    slots: usize,
    /// Directly called functions, by global index.
    callees: BTreeSet<u32>,
    /// Type indices reached through `call_indirect`.
    indirect: BTreeSet<u32>,
}

/// Everything the two passes collect about a core module.
#[derive(Default)]
struct ModuleFacts {
    /// Type index per function, imports first.
    func_types: Vec<u32>,
    /// Parameter count per type index.
    type_params: Vec<usize>,
    imported_funcs: usize,
    /// Functions reachable through a table.
    table_funcs: BTreeSet<u32>,
    /// One entry per local function, in code-section order.
    funcs: Vec<FuncFacts>,
}

/// The modelled native frame of a function with `slots` value slots.
const fn frame_bytes(slots: usize) -> usize {
    profile::STACK_FRAME_OVERHEAD_BYTES + profile::STACK_BYTES_PER_SLOT * slots
}

/// Proves a core module cannot exhaust the native stack.
///
/// # Errors
///
/// [`ProfileError::Structural`] for a frame past the per-function bound, a
/// cyclic call graph, or a path that does not fit the budget.
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

    // Type-directed indirect targets: a `call_indirect` of type T reaches
    // exactly the table-reachable functions whose own type is T.
    let mut by_type: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for func in &facts.table_funcs {
        if let Some(ty) = facts.func_types.get(*func as usize) {
            by_type.entry(*ty).or_default().insert(*func);
        }
    }

    let imported = u32::try_from(facts.imported_funcs).unwrap_or(u32::MAX);
    let mut graph: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let mut cost: BTreeMap<u32, Cost> = BTreeMap::new();
    for (local, func) in facts.funcs.iter().enumerate() {
        let index = imported.saturating_add(u32::try_from(local).unwrap_or(u32::MAX));
        cost.insert(
            index,
            Cost {
                bytes: frame_bytes(func.slots),
                frames: 1,
            },
        );
        let edges = graph.entry(index).or_default();
        edges.extend(func.callees.iter().copied());
        for ty in &func.indirect {
            if let Some(targets) = by_type.get(ty) {
                edges.extend(targets.iter().copied());
            }
        }
    }

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
///
/// Imported functions cost nothing: they are host frames at the
/// canonical-ABI boundary, covered by the reserve rather than by this walk.
fn heaviest_path(
    graph: &BTreeMap<u32, BTreeSet<u32>>,
    cost: &BTreeMap<u32, Cost>,
) -> Result<Cost, ProfileError> {
    /// Visit state: on the current path, or finished.
    enum Mark {
        Open,
        Done(Cost),
    }

    let mut marks: BTreeMap<u32, Mark> = BTreeMap::new();
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
                Some(Mark::Open) => {
                    return Err(ProfileError::Structural(
                        "the call graph is cyclic, so no static stack bound exists".to_string(),
                    ));
                }
                None => {}
            }
            marks.insert(node, Mark::Open);
            stack.push((node, true));
            for next in graph.get(&node).into_iter().flatten() {
                match marks.get(next) {
                    Some(Mark::Done(_)) => {}
                    Some(Mark::Open) => {
                        return Err(ProfileError::Structural(
                            "the call graph is cyclic, so no static stack bound exists".to_string(),
                        ));
                    }
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

/// Types, imports, and the functions a table can reach.
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
                        facts.type_params.push(match &sub.composite_type.inner {
                            CompositeInnerType::Func(f) => f.params().len(),
                            _ => 0,
                        });
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if let TypeRef::Func(ty) = import.ty {
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
                        for func in items {
                            facts
                                .table_funcs
                                .insert(func.map_err(|e| ProfileError::Feature(e.to_string()))?);
                        }
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
            let params = facts
                .func_types
                .get(facts.imported_funcs + facts.funcs.len())
                .and_then(|ty| facts.type_params.get(*ty as usize))
                .copied()
                .unwrap_or(0);
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
