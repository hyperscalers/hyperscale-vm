//! The manifest as signed: a typed dataflow DAG, and its admission.
//!
//! Nodes are method invocations typed against the target's declared
//! parameters; edges are typed value flows with exactly one producer and
//! one consumer; constraints are declarative edge annotations. Linearity —
//! every output consumed, rest edges included — is a syntactic check, and
//! producers must precede consumers, so a cycle is inexpressible rather
//! than detected. Admission is the only path from a graph to the routing
//! view: [`admit`] type-checks the graph against package metadata and
//! lowers it to a [`Manifest`] whose edge inputs carry their static
//! resource types.

use crate::dsl::{EvalError, EvalInputs, evaluate_expr};
use crate::hash::Hasher;
use crate::manifest::{Manifest, ManifestHash, Node, NodeInput};
use crate::metadata::{InstanceRegistry, MetadataCache, PackageHash, ParamType};
use crate::route::MAX_MANIFEST_NODES;
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
                        for constraint in constraints {
                            match constraint {
                                Constraint::MinAmount(amount) => {
                                    bytes.push(2);
                                    bytes.extend(amount.to_le_bytes());
                                }
                                Constraint::MaxAmount(amount) => {
                                    bytes.push(3);
                                    bytes.extend(amount.to_le_bytes());
                                }
                                Constraint::ResourceIs(address) => {
                                    bytes.push(4);
                                    bytes.extend(address.0);
                                }
                            }
                        }
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

/// Why admission rejected a graph. Deterministic: every node reaches the
/// identical verdict.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// More nodes than an index can address.
    #[error("graph has more nodes than admission can address")]
    TooManyNodes,
    /// A call target with no registered instance.
    #[error("no instance at {0:?}")]
    UnknownInstance(Address),
    /// An instance whose package is not in the metadata cache.
    #[error("no package {0:?} in the metadata cache")]
    UnknownPackage(PackageHash),
    /// A method the target package does not declare.
    #[error("package {package:?} has no method `{method}`")]
    UnknownMethod {
        /// The package consulted.
        package: PackageHash,
        /// The method requested.
        method: String,
    },
    /// An argument count differing from the declared parameters.
    #[error("node {node} passes {found} arguments, method takes {expected}")]
    ArityMismatch {
        /// The offending node.
        node: u32,
        /// Declared parameter count.
        expected: usize,
        /// Bound argument count.
        found: usize,
    },
    /// A literal of the wrong kind.
    #[error("node {node} argument {param}: expected {expected}, found {found}")]
    ParamKind {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
        /// The declared kind.
        expected: &'static str,
        /// The bound value's kind.
        found: &'static str,
    },
    /// An edge bound to a parameter that is not a bucket.
    #[error("node {node} argument {param}: an edge cannot bind a value parameter")]
    EdgeForValueParam {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
    },
    /// A literal bound to a bucket parameter.
    #[error("node {node} argument {param}: a bucket parameter needs an edge")]
    LiteralForBucketParam {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
    },
    /// An edge whose producer is not an earlier node — the shape a cycle
    /// would need, rejected structurally.
    #[error("node {node} consumes an edge from node {producer}, which is not earlier")]
    ForwardEdge {
        /// The consuming node.
        node: u32,
        /// The claimed producer.
        producer: u32,
    },
    /// An edge naming an output slot the producer does not have.
    #[error("node {producer} has no output {output}")]
    NoSuchOutput {
        /// The producing node.
        producer: u32,
        /// The claimed output slot.
        output: u32,
    },
    /// An output consumed by more than one argument.
    #[error("output {output} of node {producer} is consumed twice")]
    DoubleConsumption {
        /// The producing node.
        producer: u32,
        /// The output slot.
        output: u32,
    },
    /// An output no argument consumes — a dangling edge; rest edges must
    /// be routed like any other.
    #[error("output {output} of node {producer} is never consumed")]
    UnconsumedOutput {
        /// The producing node.
        producer: u32,
        /// The output slot.
        output: u32,
    },
    /// A constraint set no execution could satisfy.
    #[error("node {node} argument {param}: constraints are unsatisfiable")]
    UnsatisfiableConstraint {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
    },
    /// A resource constraint contradicting the edge's static type.
    #[error("node {node} argument {param}: resource constraint contradicts the edge type")]
    ResourceMismatch {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
    },
    /// An output-type expression that did not evaluate to an address.
    #[error("node {node} output {output} is not typed by a resource address")]
    OutputType {
        /// The producing node.
        node: u32,
        /// The output slot.
        output: u32,
    },
    /// An output-type expression that failed to evaluate.
    #[error("evaluating output types of node {node}")]
    Eval {
        /// The offending node.
        node: u32,
        /// The evaluation failure.
        #[source]
        source: EvalError,
    },
}

/// Admit a graph: check well-formedness, linearity, and type agreement
/// against package metadata, and lower it to the routing manifest.
///
/// # Errors
///
/// Any [`AdmissionError`]; verdicts are deterministic and identical on
/// every node.
#[allow(clippy::too_many_lines)] // one pass over nodes, one check per rule
pub fn admit(
    graph: &ManifestGraph,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
) -> Result<Manifest, AdmissionError> {
    if graph.nodes.len() > MAX_MANIFEST_NODES {
        return Err(AdmissionError::TooManyNodes);
    }
    let graph_hash = graph.hash(hasher);

    // Per prior node: its evaluated output resource types and a consumption
    // count per output slot.
    let mut outputs: Vec<Vec<Address>> = Vec::with_capacity(graph.nodes.len());
    let mut consumed: Vec<Vec<u32>> = Vec::with_capacity(graph.nodes.len());
    let mut lowered = Vec::with_capacity(graph.nodes.len());

    for (index, node) in graph.nodes.iter().enumerate() {
        let node_index = u32::try_from(index).map_err(|_| AdmissionError::TooManyNodes)?;
        let meta = instances
            .get(node.target)
            .ok_or(AdmissionError::UnknownInstance(node.target))?;
        let package = cache
            .get(meta.package)
            .ok_or(AdmissionError::UnknownPackage(meta.package))?;
        let signature =
            package
                .methods
                .get(&node.method)
                .ok_or_else(|| AdmissionError::UnknownMethod {
                    package: meta.package,
                    method: node.method.clone(),
                })?;
        if signature.params.len() != node.args.len() {
            return Err(AdmissionError::ArityMismatch {
                node: node_index,
                expected: signature.params.len(),
                found: node.args.len(),
            });
        }

        let mut bound = Vec::with_capacity(node.args.len());
        let mut inputs = Vec::with_capacity(node.args.len());
        for (position, (arg, param)) in node.args.iter().zip(&signature.params).enumerate() {
            let param_index = u32::try_from(position).map_err(|_| AdmissionError::TooManyNodes)?;
            match arg {
                GraphArg::Literal(value) => {
                    if *param == ParamType::Bucket {
                        return Err(AdmissionError::LiteralForBucketParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    if !param.admits(value) {
                        return Err(AdmissionError::ParamKind {
                            node: node_index,
                            param: param_index,
                            expected: param.name(),
                            found: value.kind(),
                        });
                    }
                    bound.push(value.clone());
                    inputs.push(NodeInput::Literal(value.clone()));
                }
                GraphArg::Edge { edge, constraints } => {
                    if *param != ParamType::Bucket {
                        return Err(AdmissionError::EdgeForValueParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    if edge.producer >= node_index {
                        return Err(AdmissionError::ForwardEdge {
                            node: node_index,
                            producer: edge.producer,
                        });
                    }
                    let producer =
                        usize::try_from(edge.producer).map_err(|_| AdmissionError::TooManyNodes)?;
                    let output =
                        usize::try_from(edge.output).map_err(|_| AdmissionError::TooManyNodes)?;
                    let resource =
                        *outputs[producer]
                            .get(output)
                            .ok_or(AdmissionError::NoSuchOutput {
                                producer: edge.producer,
                                output: edge.output,
                            })?;
                    consumed[producer][output] += 1;
                    if consumed[producer][output] > 1 {
                        return Err(AdmissionError::DoubleConsumption {
                            producer: edge.producer,
                            output: edge.output,
                        });
                    }
                    check_constraints(constraints, resource, node_index, param_index)?;
                    bound.push(Value::Bucket { resource });
                    inputs.push(NodeInput::Edge {
                        source: edge.producer,
                        resource,
                    });
                }
            }
        }

        // Evaluate this node's output resource types over its bound inputs.
        let eval_inputs = EvalInputs {
            self_addr: node.target,
            args: &bound,
            config: &meta.config,
            node_index,
            manifest_hash: graph_hash,
        };
        let mut node_outputs = Vec::with_capacity(signature.outputs.len());
        for (slot, expr) in signature.outputs.iter().enumerate() {
            let slot_index = u32::try_from(slot).map_err(|_| AdmissionError::TooManyNodes)?;
            let value = evaluate_expr(expr, &eval_inputs, hasher).map_err(|source| {
                AdmissionError::Eval {
                    node: node_index,
                    source,
                }
            })?;
            let Value::Address(resource) = value else {
                return Err(AdmissionError::OutputType {
                    node: node_index,
                    output: slot_index,
                });
            };
            node_outputs.push(resource);
        }
        consumed.push(vec![0; node_outputs.len()]);
        outputs.push(node_outputs);
        lowered.push(Node {
            target: node.target,
            method: node.method.clone(),
            inputs,
        });
    }

    // Linearity: nothing dangles.
    for (producer, counts) in consumed.iter().enumerate() {
        for (output, count) in counts.iter().enumerate() {
            if *count == 0 {
                return Err(AdmissionError::UnconsumedOutput {
                    producer: u32::try_from(producer).unwrap_or(u32::MAX),
                    output: u32::try_from(output).unwrap_or(u32::MAX),
                });
            }
        }
    }

    Ok(Manifest { nodes: lowered })
}

fn check_constraints(
    constraints: &[Constraint],
    resource: Address,
    node: u32,
    param: u32,
) -> Result<(), AdmissionError> {
    let mut min = None;
    let mut max = None;
    for constraint in constraints {
        match constraint {
            Constraint::MinAmount(amount) => min = Some(*amount),
            Constraint::MaxAmount(amount) => max = Some(*amount),
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
    Ok(())
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
