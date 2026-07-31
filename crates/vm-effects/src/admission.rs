//! Admission: the judgement that turns a signed form into a routing
//! manifest.
//!
//! One checker serves both signed forms. A bare graph is the degenerate
//! envelope — a single intent with no parameters and no subintents — and a
//! composed tree is several intents joined by typed yield edges, so
//! [`admit_intents`] takes a slice of [`IntentView`] and everything below
//! it is shape-agnostic: bindings and parameter consumption per intent,
//! a deterministic interleave along the yield edges, then one pass over
//! the flattened node order checking arity, kinds, linearity, and
//! constraints.
//!
//! Nothing here reads state. Verdicts are a pure function of the signed
//! form and content-addressed metadata, which is what lets every node
//! reach the identical one.

use crate::dsl::{EvalError, EvalInputs, evaluate_expr};
use crate::envelope::{YieldBinding, YieldParam};
use crate::graph::{Constraint, GraphArg, ManifestGraph};
use crate::hash::Hasher;
use crate::manifest::{Manifest, ManifestHash, Node, NodeInput};
use crate::metadata::{InstanceRegistry, MetadataCache, PackageHash, ParamType};
use crate::route::MAX_MANIFEST_NODES;
use crate::types::{Address, MAX_VALUE_DEPTH, Value};

/// The bound on yield parameters one intent may declare.
///
/// An intent binds one edge per parameter, so this bounds the binding
/// vector too — which is what makes every parameter position expressible
/// as a `u32` index by construction rather than by hope.
pub const MAX_YIELD_PARAMS: usize = 32;

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
    /// An intent declaring more yield parameters than [`MAX_YIELD_PARAMS`].
    #[error("intent {intent} declares more than {MAX_YIELD_PARAMS} yield parameters")]
    TooManyYieldParams {
        /// The declaring intent.
        intent: u32,
    },
    /// A yield parameter bound to a method parameter that is not a bucket.
    #[error("node {node} argument {param}: a yield parameter cannot bind a value parameter")]
    ParamForValueParam {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
    },
    /// A literal nested past [`MAX_VALUE_DEPTH`].
    #[error("node {node} argument {param}: literal nests deeper than {MAX_VALUE_DEPTH}")]
    ValueTooDeep {
        /// The offending node, in the intent's own numbering.
        node: u32,
        /// The argument position.
        param: u32,
    },
}

/// Reject literals nested past [`MAX_VALUE_DEPTH`].
///
/// Runs before the graph hash, not after: the hash feeds on literal bytes,
/// so bounding them first is what keeps admission's one unvalidated step
/// over bounded input.
pub(crate) fn check_value_depth(graph: &ManifestGraph) -> Result<(), AdmissionError> {
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
    check_value_depth(graph)?;
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

/// Check an edge's constraints against its static resource type.
///
/// Repeated bounds fold to their conjunction — the greatest lower bound
/// and the least upper bound — because execution enforces every
/// constraint in the list, not the last of each kind.
pub(crate) fn check_constraints(
    constraints: &[Constraint],
    resource: Address,
    node: u32,
    param: u32,
) -> Result<(), AdmissionError> {
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
    Ok(())
}

/// One intent as the shared admission checker consumes it.
pub(crate) struct IntentView<'a> {
    pub graph: &'a ManifestGraph,
    pub params: &'a [YieldParam],
    pub bindings: &'a [YieldBinding],
}

/// Check every intent's bindings and parameter consumption, interleave
/// the intents into one flattened node order along the yield edges, and
/// run the node-by-node admission check over that order.
#[allow(clippy::too_many_lines)] // one pass over nodes, one check per rule
pub(crate) fn admit_intents(
    intents: &[IntentView<'_>],
    identity: ManifestHash,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
) -> Result<Manifest, AdmissionError> {
    let total: usize = intents.iter().map(|view| view.graph.nodes.len()).sum();
    if total > MAX_MANIFEST_NODES {
        return Err(AdmissionError::TooManyNodes);
    }

    // Bindings and parameter consumption, intent by intent: one binding
    // per declared parameter, every binding naming a real source, every
    // parameter consumed by exactly one node argument.
    for (index, intent) in intents.iter().enumerate() {
        if intent.params.len() > MAX_YIELD_PARAMS {
            return Err(AdmissionError::TooManyYieldParams {
                intent: u32::try_from(index).expect("intents are bounded by MAX_SUBINTENTS"),
            });
        }
        let intent_index = u32::try_from(index).expect("intents are bounded by MAX_SUBINTENTS");
        if intent.bindings.len() != intent.params.len() {
            return Err(AdmissionError::BindingArity {
                intent: intent_index,
                expected: intent.params.len(),
                found: intent.bindings.len(),
            });
        }
        for (position, binding) in intent.bindings.iter().enumerate() {
            let param = u32::try_from(position).expect("bounded by MAX_YIELD_PARAMS");
            let source = usize::try_from(binding.intent)
                .ok()
                .and_then(|source| intents.get(source));
            let producer = usize::try_from(binding.edge.producer).unwrap_or(usize::MAX);
            if source.is_none_or(|source| producer >= source.graph.nodes.len()) {
                return Err(AdmissionError::UnknownYieldSource {
                    intent: intent_index,
                    param,
                });
            }
        }
        let mut uses = vec![0u32; intent.params.len()];
        for node in &intent.graph.nodes {
            for arg in &node.args {
                if let GraphArg::Param(param) = arg
                    && let Some(count) = usize::try_from(*param)
                        .ok()
                        .and_then(|position| uses.get_mut(position))
                {
                    *count += 1;
                }
            }
        }
        for (position, count) in uses.iter().enumerate() {
            let param = u32::try_from(position).expect("bounded by MAX_YIELD_PARAMS");
            match count {
                0 => {
                    return Err(AdmissionError::UnusedYieldParam {
                        intent: intent_index,
                        param,
                    });
                }
                1 => {}
                _ => {
                    return Err(AdmissionError::YieldParamReused {
                        intent: intent_index,
                        param,
                    });
                }
            }
        }
    }

    // Deterministic interleave: repeatedly emit the lowest-indexed
    // intent whose next node has every yield dependency satisfied.
    // Intents keep their author order, so acyclicity is judged at yield
    // granularity; a stall is a cycle.
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
            for arg in &node.args {
                let GraphArg::Param(param) = arg else {
                    continue;
                };
                // An out-of-range parameter carries no dependency; the
                // node check below rejects it.
                let Some(binding) = usize::try_from(*param)
                    .ok()
                    .and_then(|position| intent.bindings.get(position))
                else {
                    continue;
                };
                let source = usize::try_from(binding.intent).unwrap_or(usize::MAX);
                let producer = usize::try_from(binding.edge.producer).unwrap_or(usize::MAX);
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
            return Err(AdmissionError::CyclicYields);
        }
    }

    // Per emitted node: evaluated output resource types and a
    // consumption count per output slot, indexed by flattened position.
    let mut outputs: Vec<Vec<Address>> = Vec::with_capacity(total);
    let mut consumed: Vec<Vec<u32>> = Vec::with_capacity(total);
    let mut lowered: Vec<Node> = Vec::with_capacity(total);

    for &(intent_index, local_index) in &order {
        let intent = &intents[intent_index];
        let node = &intent.graph.nodes[local_index];
        let node_index = u32::try_from(lowered.len()).map_err(|_| AdmissionError::TooManyNodes)?;
        let local = u32::try_from(local_index).map_err(|_| AdmissionError::TooManyNodes)?;
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
                    if edge.producer >= local {
                        return Err(AdmissionError::ForwardEdge {
                            node: node_index,
                            producer: edge.producer,
                        });
                    }
                    let producer =
                        usize::try_from(edge.producer).map_err(|_| AdmissionError::TooManyNodes)?;
                    let source = flat_of[intent_index][producer];
                    let flat = usize::try_from(source).map_err(|_| AdmissionError::TooManyNodes)?;
                    let output =
                        usize::try_from(edge.output).map_err(|_| AdmissionError::TooManyNodes)?;
                    let resource =
                        *outputs[flat]
                            .get(output)
                            .ok_or(AdmissionError::NoSuchOutput {
                                producer: source,
                                output: edge.output,
                            })?;
                    consumed[flat][output] += 1;
                    if consumed[flat][output] > 1 {
                        return Err(AdmissionError::DoubleConsumption {
                            producer: source,
                            output: edge.output,
                        });
                    }
                    check_constraints(constraints, resource, node_index, param_index)?;
                    bound.push(Value::Bucket { resource });
                    inputs.push(NodeInput::Edge { source, resource });
                }
                GraphArg::Param(reference) => {
                    let Some((decl, binding)) =
                        usize::try_from(*reference).ok().and_then(|position| {
                            Some((intent.params.get(position)?, intent.bindings.get(position)?))
                        })
                    else {
                        return Err(AdmissionError::UnboundParam {
                            node: node_index,
                            param: *reference,
                        });
                    };
                    if *param != ParamType::Bucket {
                        return Err(AdmissionError::ParamForValueParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    let source_intent = usize::try_from(binding.intent)
                        .map_err(|_| AdmissionError::TooManyNodes)?;
                    let producer = usize::try_from(binding.edge.producer)
                        .map_err(|_| AdmissionError::TooManyNodes)?;
                    let source = flat_of[source_intent][producer];
                    let flat = usize::try_from(source).map_err(|_| AdmissionError::TooManyNodes)?;
                    let output = usize::try_from(binding.edge.output)
                        .map_err(|_| AdmissionError::TooManyNodes)?;
                    let resource =
                        *outputs[flat]
                            .get(output)
                            .ok_or(AdmissionError::NoSuchOutput {
                                producer: source,
                                output: binding.edge.output,
                            })?;
                    if resource != decl.resource {
                        return Err(AdmissionError::YieldResourceMismatch {
                            intent: u32::try_from(intent_index)
                                .expect("intents are bounded by MAX_SUBINTENTS"),
                            param: *reference,
                        });
                    }
                    consumed[flat][output] += 1;
                    if consumed[flat][output] > 1 {
                        return Err(AdmissionError::DoubleConsumption {
                            producer: source,
                            output: binding.edge.output,
                        });
                    }
                    check_constraints(&decl.constraints, resource, node_index, param_index)?;
                    bound.push(Value::Bucket { resource });
                    inputs.push(NodeInput::Edge { source, resource });
                }
            }
        }

        // Evaluate this node's output resource types over its bound
        // inputs.
        let eval_inputs = EvalInputs {
            self_addr: node.target,
            args: &bound,
            config: &meta.config,
            node_index,
            frame: 0,
            identity,
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

    // Linearity: nothing dangles, yields included.
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
