//! Composition: what a signed form is, before anything is judged.
//!
//! Shape-agnostic by design. A bare graph is one intent with no sockets
//! and nothing offered into it, a tree is several joined through the
//! interfaces they declare and resolved to the nodes that fill them,
//! and nothing here reads a signature — fills, socket consumption, the
//! deterministic interleave over the sockets and gives each node names,
//! and the bounds an envelope's own inputs have to clear before any of
//! it runs.

use hyperscale_vm_types::{IntentHash, PrincipalAddr, ResourceAddr};

use super::tree::Interface;
use super::{AdmissionError, MAX_SOCKETS};
use crate::envelope::Socket;
use crate::graph::{Constraint, EdgeRef, GraphArg, ManifestGraph};
use crate::hash::Hash32;
use crate::instance::InstanceMeta;
use crate::manifest::{Bounds, NodeInput};
use crate::resource::ResourceKind;
use crate::signature::ParamType;
use crate::types::{EdgeContent, MAX_VALUE_DEPTH, Value};

/// Reject presented instance records whose configuration values nest
/// past [`MAX_VALUE_DEPTH`] — the same bound graph literals clear,
/// judged here so composing the per-envelope registry never meets a
/// value the vocabulary's own encoders refuse.
pub fn check_instance_value_depth(records: &[InstanceMeta]) -> Result<(), AdmissionError> {
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
    // `flat` indexes unchecked: it comes off the interleave's own
    // numbering, which never names a node it has not emitted.
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

/// Check an edge's constraints against its static resource type and fold
/// them for execution.
///
/// Repeated bounds fold to their conjunction — the greatest lower bound
/// and the least upper bound — because every constraint in the list
/// binds, not the last of each kind. Admission can only judge the bounds
/// against each other: the amount does not exist until the producer runs,
/// so the conjunction rides the lowered edge and the manifest walk
/// enforces it against what the producer actually returned.
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

/// What fills one socket, followed to the node or the account that
/// ultimately stands behind it.
///
/// The tree resolves every composer's wiring to this before anything
/// is ordered or lowered, so the checker below sees a flat list of
/// intents whose sockets are filled from named nodes — the same view a
/// bare graph presents with no sockets at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fill {
    /// The `output`-th edge of node `producer` inside `intent`.
    Value {
        /// The producing intent, by its position in the tree.
        intent: u32,
        /// The produced edge within that intent's graph.
        edge: EdgeRef,
        /// The constraints of every socket the edge passed through on
        /// its way here, each signed by the intent that declared it.
        /// Bound beside the consuming socket's own.
        through: Vec<Constraint>,
    },
    /// A claim `intent` stands behind: proved by one of its nodes, or
    /// granted from an account it acts as.
    Authority {
        /// The supplying intent, numbered as above.
        intent: u32,
        /// What in it stands behind the claim.
        from: Proven,
    },
}

/// What inside the supplying intent stands behind a filled authority
/// socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proven {
    /// The claim node `producer` of that intent proves.
    Node(u32),
    /// An account that intent acts as, granted by the signer who signed
    /// it: the account's shard attested the keys, so the claim stands
    /// before any node runs.
    Account(PrincipalAddr),
}

impl Fill {
    /// The intent this fill sources from.
    pub(crate) const fn intent(&self) -> u32 {
        match self {
            Self::Value { intent, .. } | Self::Authority { intent, .. } => *intent,
        }
    }

    /// The node within it, where the fill names one.
    ///
    /// A grant names none: an account's authority stands before any node
    /// runs, so the socket it fills waits on nothing and the interleave
    /// has no edge to draw.
    pub(crate) const fn producer(&self) -> Option<u32> {
        match self {
            Self::Value { edge, .. } => Some(edge.producer),
            Self::Authority {
                from: Proven::Node(producer),
                ..
            } => Some(*producer),
            Self::Authority {
                from: Proven::Account(_),
                ..
            } => None,
        }
    }
}

/// One intent as the shared admission checker consumes it.
pub struct IntentView<'a> {
    pub(crate) graph: &'a ManifestGraph,
    pub(crate) sockets: &'a [Socket],
    /// What fills this intent's sockets, and where its members' gives
    /// come from, resolved by the tree.
    pub(crate) interface: &'a Interface,
    /// The accounts this intent acts as: the owners of its nullifiers,
    /// the owners of the `auth` cells its sign-ins are judged against,
    /// and the subjects its signature resolves to.
    pub(crate) accounts: &'a [PrincipalAddr],
    /// The principals whose keys attested this intent.
    ///
    /// Separate from the accounts, and that separation is the whole of
    /// what a sign-in decides: a key reaching for an account it does not
    /// derive is admissible here and refused by that account's own shard,
    /// which is what lets an account's rule name somebody else's key.
    pub(crate) attested_by: &'a [PrincipalAddr],
    /// What this intent's own signer signed: the intent's hash for an
    /// intent of a tree, and the graph's own for a bare one.
    ///
    /// Carried so a cell keyed by a node can be keyed by content that
    /// node's signer chose. A transaction hash covers a whole
    /// composition the composer assembles, which is material a party
    /// other than the cell's owner can grind.
    pub(crate) identity: IntentHash,
    /// When what this intent's signature brought into being stops being
    /// owed: the window its own signer signed plus the artifact grace,
    /// on [`intent_expiry_ms`](crate::intent_expiry_ms)'s terms. The
    /// other half of the material a node's cells are keyed by, and
    /// carried here for the reason the identity is.
    pub(crate) expiry_ms: u64,
}

impl<'a> IntentView<'a> {
    /// A view for ordering alone: the interleave and the fill checks
    /// read the graph, the sockets and the interface, and nothing else.
    ///
    /// The accounts and the identity are what admission adds, and a
    /// view built here reaches neither — which is why they are stated
    /// once, here, rather than as a placeholder at each call site that
    /// would read as a fact about the intent.
    pub(crate) const fn for_ordering(
        graph: &'a ManifestGraph,
        sockets: &'a [Socket],
        interface: &'a Interface,
    ) -> Self {
        Self {
            graph,
            sockets,
            interface,
            accounts: &[],
            attested_by: &[],
            identity: IntentHash(Hash32([0; 32])),
            expiry_ms: 0,
        }
    }

    /// The fill of `socket`, where the intent declares one.
    pub(crate) fn fill(&self, socket: u32) -> Option<&'a Fill> {
        self.interface.fills.get(usize::try_from(socket).ok()?)
    }
}

/// Fills and parameter consumption, intent by intent: one fill per
/// socket, every fill naming a real source, every socket consumed by
/// exactly one node argument or pass-through where it carries value and
/// by at least one where it carries authority.
pub(super) fn check_bindings(intents: &[IntentView<'_>]) -> Result<(), AdmissionError> {
    for (index, intent) in intents.iter().enumerate() {
        if intent.sockets.len() > MAX_SOCKETS {
            return Err(AdmissionError::TooManySockets {
                intent: u32::try_from(index).expect("intents are bounded by MAX_INTENTS"),
            });
        }
        let intent_index = u32::try_from(index).expect("intents are bounded by MAX_INTENTS");
        let fills = &intent.interface.fills;
        if fills.len() != intent.sockets.len() {
            return Err(AdmissionError::BindingArity {
                intent: intent_index,
                expected: intent.sockets.len(),
                found: fills.len(),
            });
        }
        for (position, fill) in fills.iter().enumerate() {
            let socket = u32::try_from(position).expect("bounded by MAX_SOCKETS");
            let unknown = || AdmissionError::UnknownBinding {
                intent: intent_index,
                socket,
            };
            let Some(source) = usize::try_from(fill.intent())
                .ok()
                .and_then(|source| intents.get(source))
            else {
                return Err(unknown());
            };
            // A fill naming a node is bounded by that intent's graph; a
            // grant names none, and what bounded it was the tree.
            if let Some(producer) = fill.producer() {
                let producer = usize::try_from(producer).unwrap_or(usize::MAX);
                if producer >= source.graph.nodes.len() {
                    return Err(unknown());
                }
            }
            // The fill's channel against the socket's declared one. The
            // tree refuses the mismatch where the wiring is read, so
            // every later destructure over the pair holds by
            // construction; held here too, since a bare graph's view is
            // built by hand.
            let declared = &intent.sockets[position];
            let agreed = matches!(
                (declared, fill),
                (Socket::Value { .. }, Fill::Value { .. })
                    | (Socket::Authority(_), Fill::Authority { .. })
            );
            if !agreed {
                return Err(AdmissionError::SocketKindMismatch {
                    intent: intent_index,
                    socket,
                    declared: match declared {
                        Socket::Value { .. } => "value",
                        Socket::Authority(_) => "authority",
                    },
                    offered: match fill {
                        Fill::Value { .. } => "an edge",
                        Fill::Authority { .. } => "a proof",
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
        for (count, wired) in uses.iter_mut().zip(&intent.interface.wired_uses) {
            *count += wired;
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
            // Every socket and every give this node reaches, whichever
            // way it reaches one: an argument consuming the edge that
            // fills a socket or that a member gives, and evidence
            // presenting the proof that fills a socket. Each is a
            // dependency on the node behind it, and a proof left out of
            // this scan would let a node present a claim proven after
            // it ran.
            //
            // An out-of-range reference carries no dependency; the node
            // check below rejects it. A grant stands before any node
            // runs, so the socket it fills waits on nothing.
            let waits_on = node
                .sockets()
                .filter_map(|socket| {
                    let fill = intent.fill(socket)?;
                    Some((fill.intent(), fill.producer()?))
                })
                .chain(node.gives().filter_map(|give| {
                    let yielded = intent.interface.give(give)?;
                    Some((yielded.intent, yielded.edge.producer))
                }));
            for (source, producer) in waits_on {
                let source = usize::try_from(source).unwrap_or(usize::MAX);
                let producer = usize::try_from(producer).unwrap_or(usize::MAX);
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
