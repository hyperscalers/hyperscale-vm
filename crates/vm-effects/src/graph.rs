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

use crate::dsl::EvalError;
use crate::envelope::{IntentView, admit_intents};
use crate::hash::Hasher;
use crate::manifest::{Manifest, ManifestHash};
use crate::metadata::{InstanceRegistry, MetadataCache, PackageHash};
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

/// Why admission rejected a graph or an envelope tree.
///
/// Deterministic: every node reaches the identical verdict. Node
/// indices refer to the flattened manifest admission lowers to; for a
/// bare graph the two numberings coincide.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// More nodes than an index can address.
    #[error("graph has more nodes than admission can address")]
    TooManyNodes,
    /// More subintents than an envelope may bind.
    #[error("envelope binds more subintents than admission accepts")]
    TooManySubintents,
    /// The same signed subintent bound twice into one envelope.
    #[error("subintent {index} duplicates an earlier one")]
    DuplicateSubintent {
        /// The offending subintent's index.
        index: u32,
    },
    /// An intent whose bindings do not match its declared parameters.
    #[error("intent {intent} declares {expected} parameters, binds {found}")]
    BindingArity {
        /// The intent: `0` is the root, `i + 1` is subintent `i`.
        intent: u32,
        /// Declared parameter count.
        expected: usize,
        /// Bound yield edge count.
        found: usize,
    },
    /// A yield binding naming an intent or node that does not exist.
    #[error("intent {intent} parameter {param} binds a nonexistent yield source")]
    UnknownYieldSource {
        /// The consuming intent.
        intent: u32,
        /// The parameter position.
        param: u32,
    },
    /// A yield edge carrying a different resource than the parameter
    /// declares.
    #[error("intent {intent} parameter {param}: yielded resource differs from the declared type")]
    YieldResourceMismatch {
        /// The consuming intent.
        intent: u32,
        /// The parameter position.
        param: u32,
    },
    /// A declared parameter no node argument consumes — the yielded
    /// bucket would dangle.
    #[error("intent {intent} parameter {param} is never consumed")]
    UnusedYieldParam {
        /// The declaring intent.
        intent: u32,
        /// The parameter position.
        param: u32,
    },
    /// A declared parameter consumed by more than one node argument.
    #[error("intent {intent} parameter {param} is consumed twice")]
    YieldParamReused {
        /// The declaring intent.
        intent: u32,
        /// The parameter position.
        param: u32,
    },
    /// A parameter reference past the intent's declared parameters — in
    /// a bare graph, any parameter reference at all.
    #[error("node {node} references parameter {param}, which is not declared")]
    UnboundParam {
        /// The consuming node.
        node: u32,
        /// The referenced parameter.
        param: u32,
    },
    /// Yield edges admitting no execution order: intents wait on each
    /// other's outputs in a cycle.
    #[error("the envelope's yield edges admit no execution order")]
    CyclicYields,
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

/// An admitted transaction: the routing manifest plus the identity that
/// roots fresh-ID derivation — the signed graph's hash, so distinct
/// signed transactions never mint the same fresh key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The lowered routing manifest.
    pub manifest: Manifest,
    /// The signed graph's hash: the transaction identity every fresh
    /// derivation binds to, at admission and at routing alike.
    pub identity: ManifestHash,
}

/// Admit a graph: check well-formedness, linearity, and type agreement
/// against package metadata, and lower it to the routing manifest.
///
/// A bare graph is the degenerate envelope: one intent, no parameters,
/// no subintents, its own hash as the identity. Envelope trees go
/// through [`crate::envelope::admit_tree`], which supplies the identity
/// from the signed envelope.
///
/// # Errors
///
/// Any [`AdmissionError`]; verdicts are deterministic and identical on
/// every node.
pub fn admit(
    graph: &ManifestGraph,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    let identity = graph.hash(hasher);
    let manifest = admit_intents(
        &[IntentView {
            graph,
            params: &[],
            bindings: &[],
        }],
        identity,
        cache,
        instances,
        hasher,
    )?;
    Ok(Admitted { manifest, identity })
}

pub(crate) fn check_constraints(
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
