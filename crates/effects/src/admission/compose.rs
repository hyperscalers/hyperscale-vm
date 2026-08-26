//! Composition: what a signed form is, before anything is judged.
//!
//! Shape-agnostic by design. A bare graph is one intent with no sockets
//! and no subintents, a tree is several joined through the sockets they
//! declare, and nothing here reads a signature — bindings, socket
//! consumption, the deterministic interleave over the sockets each node
//! names, and the bounds an envelope's own inputs have to clear before
//! any of it runs.

use hyperscale_vm_types::{PrincipalAddr, ResourceAddr};

use super::{AdmissionError, MAX_SOCKETS};
use crate::envelope::{Binding, Socket};
use crate::graph::{Constraint, GraphArg, ManifestGraph};
use crate::instance::InstanceMeta;
use crate::manifest::{Bounds, NodeInput};
use crate::resource::ResourceKind;
use crate::signature::ParamType;
use crate::types::{EdgeContent, MAX_VALUE_DEPTH, Value};

/// Reject presented instance records whose configuration values nest
/// past [`MAX_VALUE_DEPTH`] — the same bound graph literals clear,
/// judged here so composing the per-envelope registry never meets a
/// value the vocabulary's own encoders refuse.
pub fn check_instance_values(records: &[InstanceMeta]) -> Result<(), AdmissionError> {
    for (index, meta) in records.iter().enumerate() {
        if meta
            .config
            .iter()
            .any(|value| value.depth() > MAX_VALUE_DEPTH)
        {
            return Err(AdmissionError::InstanceValueTooDeep {
                instance: u32::try_from(index).unwrap_or(u32::MAX),
            });
        }
    }
    Ok(())
}

/// Reject literals nested past [`MAX_VALUE_DEPTH`].
///
/// Runs before the graph hash, not after: the hash feeds on literal bytes,
/// so bounding them first is what keeps admission's one unvalidated step
/// over bounded input.
pub fn check_value_depth(graph: &ManifestGraph) -> Result<(), AdmissionError> {
    for (index, node) in graph.nodes.iter().enumerate() {
        for (position, arg) in node.args.iter().enumerate() {
            if let GraphArg::Literal(value) = arg
                && value.depth() > MAX_VALUE_DEPTH
            {
                return Err(AdmissionError::ValueTooDeep {
                    node: u32::try_from(index).unwrap_or(u32::MAX),
                    param: u32::try_from(position).unwrap_or(u32::MAX),
                });
            }
        }
    }
    Ok(())
}

/// Check an edge's constraints against its static resource type and fold
/// them for execution.
///
/// Repeated bounds fold to their conjunction — the greatest lower bound
/// and the least upper bound — because every constraint in the list
/// binds, not the last of each kind. Admission can only judge the bounds
/// against each other: the amount does not exist until the producer runs,
/// so the conjunction rides the lowered edge and the manifest walk
/// enforces it against what the producer actually returned.
/// Bind one produced edge to an edge parameter: the output lookup, the
/// consumption bookkeeping, the kind check, and the constraint bounds —
/// shared by a direct edge and one filling a socket, so neither path can
/// drop a check the other makes. `verify` is the caller's own look at
/// the resolved resource, asked before anything is consumed.
pub(super) fn bind_edge(
    outputs: &[Vec<(ResourceAddr, EdgeContent)>],
    consumed: &mut [Vec<u32>],
    (source, output): (u32, u32),
    constraints: &[Constraint],
    param: ParamType,
    (node_index, param_index): (u32, u32),
    verify: impl FnOnce(ResourceAddr) -> Result<(), AdmissionError>,
) -> Result<(Value, NodeInput), AdmissionError> {
    let flat = usize::try_from(source).map_err(|_| AdmissionError::TooManyNodes)?;
    let slot = usize::try_from(output).map_err(|_| AdmissionError::TooManyNodes)?;
    let (resource, content) =
        outputs[flat]
            .get(slot)
            .cloned()
            .ok_or(AdmissionError::NoSuchOutput {
                producer: source,
                output,
            })?;
    verify(resource)?;
    consumed[flat][slot] += 1;
    if consumed[flat][slot] > 1 {
        return Err(AdmissionError::DoubleConsumption {
            producer: source,
            output,
        });
    }
    // The producer's projection fixes what the edge carries and the
    // callee's signature fixes what it takes; a fungible cell and an id
    // cell are different shapes, so a mismatch is a graph nothing should
    // sign rather than something a guest decodes its way out of.
    let carried = ResourceKind::of(&content);
    if param.edge_kind() != Some(carried) {
        return Err(AdmissionError::ResourceKindMismatch {
            node: node_index,
            param: param_index,
            expected: param.name(),
            found: carried,
        });
    }
    let bounds = check_constraints(constraints, resource, node_index, param_index)?;
    Ok((
        Value::Bucket {
            resource,
            content: content.clone(),
        },
        NodeInput::Edge {
            source,
            output,
            resource,
            content,
            bounds,
        },
    ))
}

fn check_constraints(
    constraints: &[Constraint],
    resource: ResourceAddr,
    node: u32,
    param: u32,
) -> Result<Bounds, AdmissionError> {
    let mut min: Option<u128> = None;
    let mut max: Option<u128> = None;
    for constraint in constraints {
        match constraint {
            Constraint::MinAmount(amount) => {
                min = Some(min.map_or(*amount, |bound| bound.max(*amount)));
            }
            Constraint::MaxAmount(amount) => {
                max = Some(max.map_or(*amount, |bound| bound.min(*amount)));
            }
            Constraint::ResourceIs(address) => {
                if *address != resource {
                    return Err(AdmissionError::ResourceMismatch { node, param });
                }
            }
        }
    }
    if let (Some(min), Some(max)) = (min, max)
        && min > max
    {
        return Err(AdmissionError::UnsatisfiableConstraint { node, param });
    }
    Ok(Bounds { min, max })
}

/// One intent as the shared admission checker consumes it.
pub struct IntentView<'a> {
    pub graph: &'a ManifestGraph,
    pub sockets: &'a [Socket],
    pub bindings: &'a [Binding],
    /// Whose signature this intent carries, and so whose identity its
    /// proof names. A bare graph is unsigned and produces none.
    pub signer: Option<PrincipalAddr>,
}

/// Bindings and parameter consumption, intent by intent: one binding
/// per socket, every binding naming a real source, every
/// parameter consumed by exactly one node argument.
pub(super) fn check_bindings(intents: &[IntentView<'_>]) -> Result<(), AdmissionError> {
    for (index, intent) in intents.iter().enumerate() {
        if intent.sockets.len() > MAX_SOCKETS {
            return Err(AdmissionError::TooManySockets {
                intent: u32::try_from(index).expect("intents are bounded by MAX_SUBINTENTS"),
            });
        }
        let intent_index = u32::try_from(index).expect("intents are bounded by MAX_SUBINTENTS");
        if intent.bindings.len() != intent.sockets.len() {
            return Err(AdmissionError::BindingArity {
                intent: intent_index,
                expected: intent.sockets.len(),
                found: intent.bindings.len(),
            });
        }
        for (position, binding) in intent.bindings.iter().enumerate() {
            let socket = u32::try_from(position).expect("bounded by MAX_SOCKETS");
            let source = usize::try_from(binding.intent())
                .ok()
                .and_then(|source| intents.get(source));
            let producer = usize::try_from(binding.producer()).unwrap_or(usize::MAX);
            if source.is_none_or(|source| producer >= source.graph.nodes.len()) {
                return Err(AdmissionError::UnknownBinding {
                    intent: intent_index,
                    socket,
                });
            }
            // The binding's channel against the socket's declared one,
            // judged here so every later destructure over the pair holds
            // by construction — and so the refusal names the actual
            // mismatch instead of whichever downstream check the wrong
            // half falls out of.
            let declared = &intent.sockets[position];
            let agreed = matches!(
                (declared, binding),
                (Socket::Value { .. }, Binding::Value { .. })
                    | (Socket::Authority(_), Binding::Authority { .. })
            );
            if !agreed {
                return Err(AdmissionError::SocketKindMismatch {
                    intent: intent_index,
                    socket,
                    declared: match declared {
                        Socket::Value { .. } => "value",
                        Socket::Authority(_) => "authority",
                    },
                    offered: match binding {
                        Binding::Value { .. } => "an edge",
                        Binding::Authority { .. } => "a proof",
                    },
                });
            }
        }
        let mut uses = vec![0u32; intent.sockets.len()];
        for node in &intent.graph.nodes {
            for socket in node.sockets() {
                if let Some(count) = usize::try_from(socket)
                    .ok()
                    .and_then(|position| uses.get_mut(position))
                {
                    *count += 1;
                }
            }
        }
        for (position, count) in uses.iter().enumerate() {
            let socket = u32::try_from(position).expect("bounded by MAX_SOCKETS");
            if *count == 0 {
                return Err(AdmissionError::UnconsumedSocket {
                    intent: intent_index,
                    socket,
                });
            }
            // Value is conserved and authority is not: an edge fills one
            // argument, and presenting a claim twice says nothing
            // presenting it once does not.
            let value = matches!(intent.sockets.get(position), Some(Socket::Value { .. }));
            if value && *count > 1 {
                return Err(AdmissionError::SocketReused {
                    intent: intent_index,
                    socket,
                });
            }
        }
    }

    Ok(())
}

/// Deterministic interleave: repeatedly emit the lowest-indexed intent
/// whose next node has every socket it reaches already filled. Intents
/// keep their author order, so acyclicity is judged at socket
/// granularity; a stall is a cycle.
///
/// Returns the flattened position per (intent, local node) and the
/// emission order.
#[allow(clippy::type_complexity)] // the two halves of one interleave
pub fn interleave(
    intents: &[IntentView<'_>],
    total: usize,
) -> Result<(Vec<Vec<u32>>, Vec<(usize, usize)>), AdmissionError> {
    let mut cursor = vec![0usize; intents.len()];
    let mut flat_of: Vec<Vec<u32>> = intents
        .iter()
        .map(|view| vec![0u32; view.graph.nodes.len()])
        .collect();
    let mut order: Vec<(usize, usize)> = Vec::with_capacity(total);
    while order.len() < total {
        let mut progressed = false;
        'candidates: for (index, intent) in intents.iter().enumerate() {
            let next = cursor[index];
            let Some(node) = intent.graph.nodes.get(next) else {
                continue;
            };
            // Every socket this node reaches, whichever way it reaches
            // one: an argument consuming the edge that fills it, and
            // evidence presenting the proof that does. Both are
            // dependencies on another intent's node, and a proof left
            // out of this scan would let a node present a claim minted
            // after it ran.
            for socket in node.sockets() {
                // An out-of-range socket carries no dependency; the
                // node check below rejects it.
                let Some(binding) = usize::try_from(socket)
                    .ok()
                    .and_then(|position| intent.bindings.get(position))
                else {
                    continue;
                };
                let source = usize::try_from(binding.intent()).unwrap_or(usize::MAX);
                let producer = usize::try_from(binding.producer()).unwrap_or(usize::MAX);
                if cursor
                    .get(source)
                    .is_none_or(|&emitted| producer >= emitted)
                {
                    continue 'candidates;
                }
            }
            flat_of[index][next] =
                u32::try_from(order.len()).map_err(|_| AdmissionError::TooManyNodes)?;
            order.push((index, next));
            cursor[index] += 1;
            progressed = true;
            break;
        }
        if !progressed {
            return Err(AdmissionError::CyclicSockets);
        }
    }

    Ok((flat_of, order))
}
