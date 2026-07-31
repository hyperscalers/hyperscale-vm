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

use crate::hash::Hasher;
use crate::manifest::ManifestHash;
use crate::types::{Address, Value};

/// One produced value edge: the `output`-th edge of the `producer` node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeRef {
    /// The producing node's index.
    pub producer: u32,
    /// The output slot on the producer.
    pub output: u32,
}

/// A declarative edge annotation, checked at admission where static and at
/// execution otherwise. The same constraint language binds subintent
/// yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Constraint {
    /// The edge must carry at least this amount at execution.
    MinAmount(u128),
    /// The edge must carry at most this amount at execution.
    MaxAmount(u128),
    /// The edge's static resource type must be exactly this — checked at
    /// admission.
    ResourceIs(Address),
}

/// One bound argument of a graph node.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// A method invocation node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphNode {
    /// The target instance, named in the manifest.
    pub target: Address,
    /// The method to invoke.
    pub method: String,
    /// The bound arguments, in parameter order.
    pub args: Vec<GraphArg>,
}

/// The typed dataflow DAG a transaction signs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestGraph {
    /// Invocation nodes; every edge's producer index is smaller than its
    /// consumer's.
    pub nodes: Vec<GraphNode>,
}

const DOMAIN_GRAPH_NODE: &[u8] = b"hyperscale-vm/graph-node";
const DOMAIN_GRAPH: &[u8] = b"hyperscale-vm/graph";

/// The canonical byte form of a constraint list, shared by the graph hash
/// and the subintent declaration hash.
pub(crate) fn encode_constraints(out: &mut Vec<u8>, constraints: &[Constraint]) {
    for constraint in constraints {
        match constraint {
            Constraint::MinAmount(amount) => {
                out.push(2);
                out.extend(amount.to_le_bytes());
            }
            Constraint::MaxAmount(amount) => {
                out.push(3);
                out.extend(amount.to_le_bytes());
            }
            Constraint::ResourceIs(address) => {
                out.push(4);
                out.extend(address.0);
            }
        }
    }
}

impl ManifestGraph {
    /// The graph's identity through the hasher seam; the evaluation root
    /// for output-type expressions at admission.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> ManifestHash {
        let mut node_hashes = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let mut parts: Vec<Vec<u8>> = Vec::with_capacity(2 + node.args.len());
            parts.push(node.target.0.to_vec());
            parts.push(node.method.as_bytes().to_vec());
            for arg in &node.args {
                let mut bytes = Vec::new();
                match arg {
                    GraphArg::Literal(value) => {
                        bytes.push(0);
                        bytes.extend(value.canonical_bytes());
                    }
                    GraphArg::Edge { edge, constraints } => {
                        bytes.push(1);
                        bytes.extend(edge.producer.to_le_bytes());
                        bytes.extend(edge.output.to_le_bytes());
                        encode_constraints(&mut bytes, constraints);
                    }
                    GraphArg::Param(param) => {
                        bytes.push(5);
                        bytes.extend(param.to_le_bytes());
                    }
                }
                parts.push(bytes);
            }
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
    use crate::types::{Address, Value};

    #[test]
    fn the_graph_hash_covers_edges_and_constraints() {
        let base = ManifestGraph {
            nodes: vec![
                GraphNode {
                    target: Address([1; 16]),
                    method: "withdraw".into(),
                    args: vec![GraphArg::Literal(Value::U128(5))],
                },
                GraphNode {
                    target: Address([2; 16]),
                    method: "deposit".into(),
                    args: vec![GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        constraints: vec![Constraint::MinAmount(1)],
                    }],
                },
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
