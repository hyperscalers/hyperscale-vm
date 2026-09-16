//! The manifest as signed: a typed dataflow DAG and its identity.
//!
//! Nodes are method invocations typed against the target's declared
//! parameters; edges are typed value flows with exactly one producer and
//! one consumer; constraints are declarative edge annotations. Linearity —
//! every output consumed, rest edges included — is a syntactic check, and
//! producers must precede consumers, so a cycle is inexpressible rather
//! than detected.
//!
//! This module is the signed shape and its hash. Judging it is
//! [`crate::admission`]'s job, and admission is the only path from a graph
//! to the routing view.

use std::collections::BTreeSet;

use hyperscale_hbor::{Hbor, to_vec};
use hyperscale_vm_types::{CallTarget, MAX_MANIFEST_NODES, PrincipalAddr, ResourceAddr};

use crate::hash::Hasher;
use crate::manifest::ManifestHash;
use crate::types::Value;

/// One produced value edge: the `output`-th edge of the `producer` node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct EdgeRef {
    /// The producing node's index.
    pub producer: u32,
    /// The output slot on the producer.
    pub output: u32,
}

/// One value a member offers: the `give`-th entry of the `gives` of the
/// composing intent's `member`-th member.
///
/// The one way a composer names anything inside a member. A member's
/// interface is what its signer published, so what the composer reaches
/// is a position in it and never a node of the member's graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct GiveRef {
    /// The member, by its position in the composing intent's `members`.
    pub member: u32,
    /// The give, by its position in that member's `gives`.
    pub give: u32,
}

/// A declarative edge annotation, checked at admission where static and at
/// execution otherwise. The same constraint language binds a member's
/// gives and an intent's sockets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Constraint {
    /// The edge must carry at least this amount at execution.
    MinAmount(u128),
    /// The edge must carry at most this amount at execution.
    MaxAmount(u128),
    /// The edge's static resource type must be exactly this — checked at
    /// admission.
    ResourceIs(ResourceAddr),
}

/// Where a value edge an intent consumes, wires or gives comes from:
/// one of its own graph's outputs, a give of one of its members, or one
/// of its own sockets.
///
/// The one vocabulary for every place value is named — an argument of
/// the intent's own call, the wiring that fills a member's socket, and
/// the gives the intent offers upward — so what an intent may reach is
/// said once: its own edges, its members' gives and its own sockets, and
/// nothing inside a member. Each place admits what makes sense there: a
/// give of a socket routes the composer's value back to it and is
/// refused; everything else is the intent's to spend once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum ValueRef {
    /// An output of the intent's own graph.
    Edge(EdgeRef),
    /// A give of one of the intent's members: value that flows down
    /// the tree, taken from below.
    Give(GiveRef),
    /// One of the intent's own sockets: value that flows up the tree,
    /// filled from above. Only meaningful inside a tree.
    Socket(u32),
}

impl ValueRef {
    /// The socket this names, where it names one.
    #[must_use]
    pub const fn socket(self) -> Option<u32> {
        match self {
            Self::Socket(socket) => Some(socket),
            Self::Edge(_) | Self::Give(_) => None,
        }
    }

    /// The give this names, where it names one.
    #[must_use]
    pub const fn give(self) -> Option<GiveRef> {
        match self {
            Self::Give(give) => Some(give),
            Self::Edge(_) | Self::Socket(_) => None,
        }
    }
}

/// One bound argument of a graph node.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum GraphArg {
    /// A literal from the signed envelope.
    Literal(Value),
    /// Consumption of a value edge, with the consumer's constraints on
    /// it. The edge is the intent's own, a member's give, or the fill
    /// of one of its sockets; the constraints bind beside whatever the
    /// edge's own declaration already asks.
    Value {
        /// Where the edge comes from.
        source: ValueRef,
        /// The consumer's declared constraints on it.
        constraints: Vec<Constraint>,
    },
}

impl GraphArg {
    /// Consumption of `edge`, an output of the intent's own graph.
    #[must_use]
    pub const fn edge(edge: EdgeRef, constraints: Vec<Constraint>) -> Self {
        Self::Value {
            source: ValueRef::Edge(edge),
            constraints,
        }
    }

    /// Consumption of `give`, a member's.
    #[must_use]
    pub const fn give(give: GiveRef, constraints: Vec<Constraint>) -> Self {
        Self::Value {
            source: ValueRef::Give(give),
            constraints,
        }
    }

    /// Consumption of the edge filling the intent's `socket`-th socket,
    /// under the socket's own constraints alone.
    #[must_use]
    pub const fn socket(socket: u32) -> Self {
        Self::Value {
            source: ValueRef::Socket(socket),
            constraints: Vec::new(),
        }
    }

    /// The edge this argument consumes, where it consumes one.
    #[must_use]
    pub const fn source(&self) -> Option<ValueRef> {
        match self {
            Self::Value { source, .. } => Some(*source),
            Self::Literal(_) => None,
        }
    }
}

/// The bound on identities one call may present as evidence.
///
/// A bound on pre-payment work: admission resolves each reference
/// against the intent before any fee is assured, so the list is a
/// ceiling sized against that budget rather than a charge.
pub const MAX_EVIDENCE_PER_NODE: usize = 8;

/// Where a presented proof comes from.
///
/// Evidence is presented, never ambient: a node names what it hands its
/// callee, so a call into one package cannot carry authority the author
/// meant for another. Two of the three sources are scoped to the node's
/// own intent — an account to the intent that acts as it, a node proof
/// to the intent whose node proved it. A socket is the one that is not,
/// which is why the declaration shapes it and the composition answers
/// for what fills it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum ClaimRef {
    /// The claim of an account the enclosing intent acts as. Nobody
    /// holds it and no node proves it: the account's own shard attests
    /// that the keys behind the intent are ones its stored rule admits,
    /// as a condition judged before any body runs. Refused where the
    /// intent does not act as the account.
    Account(PrincipalAddr),
    /// The proof an earlier node of the same intent proved, carrying the
    /// identity of that node's target.
    ///
    /// Admission resolves the index against the intent's own node list
    /// and refuses one that is not earlier or whose method does not prove.
    /// Nothing checks the proof later: if the producing node's own gate
    /// refuses, that node aborts the transaction, so a consumer only ever
    /// runs in a world where the producer succeeded.
    Node(u32),
    /// The proof filling this intent's `n`-th socket — the one way
    /// authority crosses an intent boundary.
    ///
    /// A node reference names a node of the same intent, and a signer
    /// signs their own intent whole, so nothing inside an intent can
    /// reach authority somebody else holds. A socket can: the
    /// declaration shapes it with the claim it wants and the composition
    /// names what supplies one, so the signer signs which authority they
    /// asked for and the composer answers for finding it.
    Socket(u32),
}

/// A method invocation node.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct GraphNode {
    /// The target instance, named in the manifest. Its class is what
    /// makes it invocable: a package is code and a resource is a supply,
    /// so neither can be written here at all.
    pub target: CallTarget,
    /// The method to invoke.
    pub method: String,
    /// The bound arguments, in parameter order.
    pub args: Vec<GraphArg>,
    /// The evidence this call presents to its callee.
    ///
    /// A set rather than a list: what a rule asks is which identities are
    /// present, so presenting one twice says nothing a decoder should have
    /// two ways to write. Empty for a method that requires no authority,
    /// and admission refuses either mismatch.
    #[hbor(max = MAX_EVIDENCE_PER_NODE)]
    pub evidence: BTreeSet<ClaimRef>,
}

impl GraphNode {
    /// Every socket this node names, whichever channel names it.
    ///
    /// The two channels a node takes from outside its own graph are
    /// parallel by construction — an argument is a literal or a value
    /// reference, and evidence is an account, a node or a socket — and
    /// what they share is exactly this: a socket makes the node depend
    /// on whatever the composition bound it to. Ordering and use
    /// counting both ask it, so it is asked in one place.
    pub(crate) fn sockets(&self) -> impl Iterator<Item = u32> + '_ {
        let args = self
            .args
            .iter()
            .filter_map(|arg| arg.source().and_then(ValueRef::socket));
        let presented = self
            .evidence
            .iter()
            .filter_map(|reference| match reference {
                ClaimRef::Socket(socket) => Some(*socket),
                ClaimRef::Account(_) | ClaimRef::Node(_) => None,
            });
        args.chain(presented)
    }

    /// Every give this node consumes.
    ///
    /// The argument channel alone: authority never travels upward, so no
    /// evidence names a member. Ordering asks it for the same reason it
    /// asks [`sockets`](Self::sockets) — a give makes the node depend on
    /// the member's node that produces it.
    pub(crate) fn gives(&self) -> impl Iterator<Item = GiveRef> + '_ {
        self.args
            .iter()
            .filter_map(|arg| arg.source().and_then(ValueRef::give))
    }

    /// A call presenting no evidence — what a method admitting anyone
    /// takes.
    #[must_use]
    pub fn new(
        target: impl Into<CallTarget>,
        method: impl Into<String>,
        args: Vec<GraphArg>,
    ) -> Self {
        Self {
            target: target.into(),
            method: method.into(),
            args,
            evidence: BTreeSet::new(),
        }
    }

    /// A call presenting `account`, one the enclosing intent acts as —
    /// what an authorizing method takes.
    #[must_use]
    pub fn signed(
        account: PrincipalAddr,
        target: impl Into<CallTarget>,
        method: impl Into<String>,
        args: Vec<GraphArg>,
    ) -> Self {
        Self {
            evidence: BTreeSet::from([ClaimRef::Account(account)]),
            ..Self::new(target, method, args)
        }
    }

    /// A call presenting the proof drawn from the intent's node `producer` —
    /// what a guarded method takes.
    #[must_use]
    pub fn bearing(
        target: impl Into<CallTarget>,
        method: impl Into<String>,
        args: Vec<GraphArg>,
        producer: u32,
    ) -> Self {
        Self {
            evidence: BTreeSet::from([ClaimRef::Node(producer)]),
            ..Self::new(target, method, args)
        }
    }
}

/// The typed dataflow DAG a transaction signs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct ManifestGraph {
    /// Invocation nodes; every edge's producer index is smaller than its
    /// consumer's.
    #[hbor(max = MAX_MANIFEST_NODES)]
    pub nodes: Vec<GraphNode>,
}

const DOMAIN_GRAPH_NODE: &[u8] = b"hyperscale-vm/graph-node";
const DOMAIN_GRAPH: &[u8] = b"hyperscale-vm/graph";

impl ManifestGraph {
    /// The graph's identity through the hasher seam; the evaluation root
    /// for output-type expressions at admission.
    ///
    /// Each node hashes as its target, its method, and one part per
    /// argument — the argument's canonical encoding, so the hashed form
    /// and the wire form are one byte string, and a constraint or an edge
    /// reference cannot mean one thing to the hash and another to a
    /// decoder.
    ///
    /// # Panics
    ///
    /// Hashed graphs pass the depth gate first, as
    /// [`Value::canonical_bytes`] requires of the literals this feeds on.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> ManifestHash {
        let mut node_hashes = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let mut parts: Vec<Vec<u8>> = Vec::with_capacity(2 + node.args.len());
            parts.push(node.target.to_bytes().to_vec());
            parts.push(node.method.as_bytes().to_vec());
            for arg in &node.args {
                parts.push(to_vec(arg).expect("hashed graphs pass the depth gate first"));
            }
            // Claim evidence is signed content: a relayer that could
            // add or drop a presentation would be choosing what authority
            // a call carries.
            parts.push(to_vec(&node.evidence).expect("a bounded set encodes"));
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            node_hashes.push(hasher.hash(DOMAIN_GRAPH_NODE, &refs));
        }
        let refs: Vec<&[u8]> = node_hashes.iter().map(|hash| hash.0.as_slice()).collect();
        ManifestHash(hasher.hash(DOMAIN_GRAPH, &refs))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::ComponentAddr;

    use super::{Constraint, EdgeRef, GraphArg, GraphNode, ManifestGraph};
    use crate::hash::TestHasher;
    use crate::types::Value;

    #[test]
    fn the_graph_hash_covers_edges_and_constraints() {
        let base = ManifestGraph {
            nodes: vec![
                GraphNode::new(
                    ComponentAddr::new([1; 31]),
                    "withdraw",
                    vec![GraphArg::Literal(Value::U128(5))],
                ),
                GraphNode::new(
                    ComponentAddr::new([2; 31]),
                    "deposit",
                    vec![GraphArg::edge(
                        EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        vec![Constraint::MinAmount(1)],
                    )],
                ),
            ],
        };
        let mut reconstrained = base.clone();
        reconstrained.nodes[1].args[0] = GraphArg::edge(
            EdgeRef {
                producer: 0,
                output: 0,
            },
            vec![Constraint::MinAmount(2)],
        );
        let h = |g: &ManifestGraph| g.hash(&TestHasher);
        assert_eq!(h(&base), h(&base));
        assert_ne!(h(&base), h(&reconstrained));
    }
}
