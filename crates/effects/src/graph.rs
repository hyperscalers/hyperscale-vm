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

use crate::hash::Hasher;
use crate::manifest::ManifestHash;
use crate::route::MAX_MANIFEST_NODES;
use crate::types::{CallTarget, ResourceRef, Value};

/// One produced value edge: the `output`-th edge of the `producer` node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct EdgeRef {
    /// The producing node's index.
    pub producer: u32,
    /// The output slot on the producer.
    pub output: u32,
}

/// A declarative edge annotation, checked at admission where static and at
/// execution otherwise. The same constraint language binds subintent
/// yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Constraint {
    /// The edge must carry at least this amount at execution.
    MinAmount(u128),
    /// The edge must carry at most this amount at execution.
    MaxAmount(u128),
    /// The edge's static resource type must be exactly this — checked at
    /// admission.
    ResourceIs(ResourceRef),
}

/// One bound argument of a graph node.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum GraphArg {
    /// A literal from the signed envelope.
    Literal(Value),
    /// Consumption of a produced edge, with its constraints.
    Edge {
        /// The consumed edge.
        edge: EdgeRef,
        /// The consumer's declared constraints on it.
        constraints: Vec<Constraint>,
    },
    /// Consumption of the enclosing intent's declared yield parameter —
    /// a typed hole the composition binds to another intent's output
    /// edge. Only meaningful inside an envelope tree; a bare graph
    /// admits no parameters.
    Param(u32),
}

/// The bound on identities one call may present as evidence.
pub const MAX_EVIDENCE_PER_NODE: usize = 8;

/// Where a presented badge comes from.
///
/// Evidence is presented, never ambient: a node names what it hands its
/// callee, so a call into one package cannot carry authority the author
/// meant for another. An intent's signature is the only thing that
/// produces a badge, and it produces one usable inside that intent alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum EvidenceRef {
    /// The badge the enclosing intent's own signature produces, carrying
    /// the identity of whoever signed that intent.
    IntentSignature,
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
    pub evidence: BTreeSet<EvidenceRef>,
}

impl GraphNode {
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

    /// A call presenting the enclosing intent's signature badge — what a
    /// guarded method takes.
    #[must_use]
    pub fn signed(
        target: impl Into<CallTarget>,
        method: impl Into<String>,
        args: Vec<GraphArg>,
    ) -> Self {
        Self {
            evidence: BTreeSet::from([EvidenceRef::IntentSignature]),
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
            // Presented evidence is signed content: a relayer that could
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
    use super::{Constraint, EdgeRef, GraphArg, GraphNode, ManifestGraph};
    use crate::hash::TestHasher;
    use crate::types::{ComponentAddr, Value};

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
                    vec![GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        constraints: vec![Constraint::MinAmount(1)],
                    }],
                ),
            ],
        };
        let mut reconstrained = base.clone();
        reconstrained.nodes[1].args[0] = GraphArg::Edge {
            edge: EdgeRef {
                producer: 0,
                output: 0,
            },
            constraints: vec![Constraint::MinAmount(2)],
        };
        let h = |g: &ManifestGraph| g.hash(&TestHasher);
        assert_eq!(h(&base), h(&base));
        assert_ne!(h(&base), h(&reconstrained));
    }
}
