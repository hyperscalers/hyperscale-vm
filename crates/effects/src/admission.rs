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
use crate::graph::{Constraint, EvidenceRef, GraphArg, ManifestGraph};
use crate::hash::Hasher;
use crate::invoke::EdgeKind;
use crate::manifest::{AuthorityGate, Bounds, Manifest, ManifestHash, Node, NodeInput, Possession};
use crate::metadata::{
    AbiError, Accessibility, CustodyClaim, GateShape, InstanceMeta, InstanceRegistry,
    MetadataCache, PackageHash, ParamType,
};
use crate::presented::Presented;
use crate::resource::holdings_collection;
use crate::route::MAX_MANIFEST_NODES;
use crate::types::{
    Address, AddressClass, EdgeContent, MAX_VALUE_DEPTH, PrincipalAddr, Value, child_key,
};
use crate::vocabulary::VAULT;

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
    /// A guarded method named with no evidence presented.
    #[error("node {node} calls a guarded method and presents no evidence")]
    MissingEvidence {
        /// The offending node.
        node: u32,
    },
    /// Evidence presented to a method that requires none.
    ///
    /// Refused rather than ignored: a presentation nothing reads would be
    /// authority travelling further than its author could see.
    #[error("node {node} presents evidence to a method that admits anyone")]
    UnexpectedEvidence {
        /// The offending node.
        node: u32,
    },
    /// A guarded method whose required identity does not evaluate to an
    /// address — a package whose declaration is unsatisfiable by anyone.
    #[error("node {node} requires an authority that is not an address")]
    AuthorityType {
        /// The offending node.
        node: u32,
    },
    /// A custodial method whose badge does not evaluate to a resource
    /// address — a gate with nothing possessable to verify.
    #[error("node {node} mints an identity that is not a resource address")]
    MintType {
        /// The offending node.
        node: u32,
    },
    /// A custodial method whose declaration is not the pinned custody
    /// shape — re-asked of the signature here for the same reason.
    #[error("node {node}: the custodial method's declaration is not the custody shape")]
    CustodyShape {
        /// The offending node.
        node: u32,
    },
    /// An authorizing method whose declaration is not the single point
    /// read its stored rule lives at — the shape the publish check pins,
    /// re-derived so a cached package that never passed one is a refusal
    /// rather than a panic.
    #[error("node {node}: the authorizing method names no rule cell")]
    RuleCell {
        /// The offending node.
        node: u32,
    },
    /// A proof drawn from an intent signature in an unsigned graph.
    #[error("node {node} presents a signature proof, and its intent is unsigned")]
    UnsignedEvidence {
        /// The offending node.
        node: u32,
    },
    /// A signature proof presented to a method that only minted proofs
    /// open.
    ///
    /// A signature signs in; a proof acts. The identity a signature
    /// proof carries is the address its key derives, and whether that
    /// address still holds its account's authority is state only the
    /// account's rule knows — so the one gate a signature may reach is
    /// an authorizing one, where that rule is read.
    #[error("node {node} presents a signature proof to a method only a minted proof opens")]
    SignatureForGuarded {
        /// The offending node.
        node: u32,
    },
    /// A proof drawn from a node that is not an earlier node of the same
    /// intent — the proof's producer must have run, and aborted the
    /// transaction if its own gate refused, before anything consumes it.
    #[error("node {node} draws a proof from node {producer}, which is not earlier")]
    ForwardProof {
        /// The consuming node, flattened.
        node: u32,
        /// The claimed producer, in the intent's own node order.
        producer: u32,
    },
    /// A proof drawn from a node whose method mints no identity.
    #[error("node {node} draws a proof from node {producer}, whose method does not mint")]
    UnmintingProof {
        /// The consuming node, flattened.
        node: u32,
        /// The producer named, in the intent's own node order.
        producer: u32,
    },
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
    /// An edge carrying one kind bound to a parameter declaring the
    /// other. The producer's projection says what crosses; the callee's
    /// signature says what it takes.
    #[error("node {node} argument {param}: a {expected} parameter cannot take a {found:?} edge")]
    EdgeKindMismatch {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
        /// The kind the parameter declares.
        expected: &'static str,
        /// The kind the producing edge carries.
        found: EdgeKind,
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
    /// A value edge carrying a resource the callee's own cells do not
    /// hold at that position.
    #[error(
        "node {node} argument {param}: the method denominates this position in {expected:?}, \
         and the edge carries {found:?}"
    )]
    Denomination {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
        /// What the callee's declaration fixes the position to.
        expected: Address,
        /// What the routed edge actually carries.
        found: Address,
    },
    /// A denomination expression that evaluated to something other than a
    /// resource address.
    #[error("node {node} argument {param} is denominated by an expression that is not a resource")]
    DenominationType {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
    },
    /// An output expression that evaluated to neither a resource address
    /// nor a bucket projection.
    #[error("node {node} output {output} is not typed by a resource or bucket")]
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
    /// A presented instance record's configuration value nested past
    /// [`MAX_VALUE_DEPTH`].
    #[error("instance record {instance}: configuration value nests deeper than {MAX_VALUE_DEPTH}")]
    InstanceValueTooDeep {
        /// Index of the record in the envelope's own order.
        instance: u32,
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

/// Reject presented instance records whose configuration values nest
/// past [`MAX_VALUE_DEPTH`] — the same bound graph literals clear,
/// judged here so composing the per-envelope registry never meets a
/// value the vocabulary's own encoders refuse.
pub(crate) fn check_instance_values(records: &[InstanceMeta]) -> Result<(), AdmissionError> {
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
///
/// Only admission constructs one, and [`crate::route`] takes nothing else,
/// so "routing consumes admitted manifests" is a fact about the types
/// rather than a convention callers are asked to keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    manifest: Manifest,
    identity: ManifestHash,
}

impl Admitted {
    pub(crate) const fn new(manifest: Manifest, identity: ManifestHash) -> Self {
        Self { manifest, identity }
    }

    /// The lowered routing manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The signed form's hash: the transaction identity every fresh
    /// derivation binds to, at admission and at routing alike.
    #[must_use]
    pub const fn identity(&self) -> ManifestHash {
        self.identity
    }
}

/// Admit a graph: check well-formedness, linearity, and type agreement
/// against package metadata, and lower it to the routing manifest.
///
/// A bare graph is the degenerate envelope: one intent signed by
/// `composer`, no parameters, no subintents, its own hash as the
/// identity. Envelope trees go
/// through [`crate::envelope::admit_tree`], which supplies the identity
/// from the signed envelope.
///
/// # Errors
///
/// Any [`AdmissionError`]; verdicts are deterministic and identical on
/// every node.
pub fn admit(
    graph: &ManifestGraph,
    composer: PrincipalAddr,
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
            signer: Some(composer.address()),
        }],
        identity,
        cache,
        instances,
        hasher,
    )?;
    Ok(Admitted::new(manifest, identity))
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
pub(crate) fn check_constraints(
    constraints: &[Constraint],
    resource: Address,
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
pub(crate) struct IntentView<'a> {
    pub graph: &'a ManifestGraph,
    pub params: &'a [YieldParam],
    pub bindings: &'a [YieldBinding],
    /// Whose signature this intent carries, and so whose identity its
    /// proof names. A bare graph is unsigned and produces none.
    pub signer: Option<Address>,
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

    // Per emitted node: evaluated output projections and a consumption
    // count per output slot, indexed by flattened position.
    let mut outputs: Vec<Vec<(Address, EdgeContent)>> = Vec::with_capacity(total);
    let mut consumed: Vec<Vec<u32>> = Vec::with_capacity(total);
    let mut lowered: Vec<Node> = Vec::with_capacity(total);
    // What each node mints, indexed by flattened position: an
    // authorizing method's own identity, a custodial method's badge, and
    // an empty set from anything else. A proof drawn from a node draws
    // the whole set, so a gate that verifies more than one thing about
    // its caller presents all of it.
    let mut minted: Vec<Vec<Presented>> = Vec::with_capacity(total);

    for &(intent_index, local_index) in &order {
        let intent = &intents[intent_index];
        let node = &intent.graph.nodes[local_index];
        let node_index = u32::try_from(lowered.len()).map_err(|_| AdmissionError::TooManyNodes)?;
        let local = u32::try_from(local_index).map_err(|_| AdmissionError::TooManyNodes)?;
        let meta = instances
            .get(node.target)
            .ok_or_else(|| AdmissionError::UnknownInstance(node.target.address()))?;
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
                    if param.is_edge() {
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
                    if !param.is_edge() {
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
                    let (resource, content) =
                        outputs[flat]
                            .get(output)
                            .cloned()
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
                    // The producer's projection fixes what the edge
                    // carries and the callee's signature fixes what it
                    // takes; a fungible cell and an id cell are different
                    // shapes, so a mismatch is a graph nothing should
                    // sign rather than something a guest decodes its way
                    // out of.
                    let carried = EdgeKind::of(&content);
                    if param.edge_kind() != Some(carried) {
                        return Err(AdmissionError::EdgeKindMismatch {
                            node: node_index,
                            param: param_index,
                            expected: param.name(),
                            found: carried,
                        });
                    }
                    let bounds = check_constraints(constraints, resource, node_index, param_index)?;
                    bound.push(Value::Bucket {
                        resource,
                        content: content.clone(),
                    });
                    inputs.push(NodeInput::Edge {
                        source,
                        output: edge.output,
                        resource,
                        content,
                        bounds,
                    });
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
                    let (resource, content) =
                        outputs[flat]
                            .get(output)
                            .cloned()
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
                    let bounds =
                        check_constraints(&decl.constraints, resource, node_index, param_index)?;
                    bound.push(Value::Bucket {
                        resource,
                        content: content.clone(),
                    });
                    inputs.push(NodeInput::Edge {
                        source,
                        output: binding.edge.output,
                        resource,
                        content,
                        bounds,
                    });
                }
            }
        }

        // Evidence presence is a property of the signed form: a guarded
        // or authorizing call presents something, a public one presents
        // nothing. Whether what it presents satisfies the target's rule
        // is the target's own business, answered where the target's
        // state is.
        if signature.accessibility.requires_evidence() {
            if node.evidence.is_empty() {
                return Err(AdmissionError::MissingEvidence { node: node_index });
            }
        } else if !node.evidence.is_empty() {
            return Err(AdmissionError::UnexpectedEvidence { node: node_index });
        }
        // What the gate judges, and what the declaration reads to judge
        // it — asked of the signature itself, so a cached package that
        // never passed the publish check is a refusal rather than an
        // ungated node. The accessor returns shape refusals alone, and
        // both rule shapes are one verdict here.
        let gate = signature.gate().map_err(|error| match error {
            AbiError::CustodialShape => AdmissionError::CustodyShape { node: node_index },
            _ => AdmissionError::RuleCell { node: node_index },
        })?;
        // A proof is scoped to the intent that produced it — a signature
        // proof to the intent whose signature, a node proof to the intent
        // whose node — so the identities resolve against this node's own
        // intent and no other.
        let mut evidence = Vec::with_capacity(node.evidence.len());
        for reference in &node.evidence {
            match reference {
                EvidenceRef::IntentSignature => {
                    // A signature signs in; a proof acts. Whether the
                    // key behind this proof still holds its account's
                    // authority is the account's rule, so the only
                    // gates it may reach are the ones that read a rule
                    // — the sign-in, and the recovery surface.
                    if !signature.accessibility.reads_a_rule() {
                        return Err(AdmissionError::SignatureForGuarded { node: node_index });
                    }
                    let signer = intent
                        .signer
                        .ok_or(AdmissionError::UnsignedEvidence { node: node_index })?;
                    evidence.push(Presented::Identity(signer));
                }
                EvidenceRef::Node(producer) => {
                    // An earlier node of the same intent, whose minted
                    // claims — the target's own statement, resolved when
                    // that node was judged — are what this proof
                    // presents. A node that minted nothing mints an
                    // empty set, which is nothing to present.
                    let flat = usize::try_from(*producer)
                        .ok()
                        .filter(|&earlier| earlier < local_index)
                        .map(|earlier| flat_of[intent_index][earlier])
                        .and_then(|flat| usize::try_from(flat).ok())
                        .ok_or(AdmissionError::ForwardProof {
                            node: node_index,
                            producer: *producer,
                        })?;
                    let claims = minted.get(flat).filter(|claims| !claims.is_empty()).ok_or(
                        AdmissionError::UnmintingProof {
                            node: node_index,
                            producer: *producer,
                        },
                    )?;
                    evidence.extend_from_slice(claims);
                }
            }
        }

        // Evaluate this node's output resource types over its bound
        // inputs.
        let eval_inputs = EvalInputs {
            self_addr: node.target.address(),
            args: &bound,
            config: &meta.config,
            node_index,
            frame: 0,
            identity,
        };
        // Judged here rather than inside the binding loop above, because a
        // denomination is an expression over the *bound* arguments: one
        // naming a later position would evaluate against a parameter that
        // loop has not reached.
        for (position, denomination) in signature.denominations.iter().enumerate() {
            let Some(expr) = denomination else { continue };
            let param = u32::try_from(position).map_err(|_| AdmissionError::TooManyNodes)?;
            let value = evaluate_expr(expr, &eval_inputs, hasher).map_err(|source| {
                AdmissionError::Eval {
                    node: node_index,
                    source,
                }
            })?;
            let Value::Address(expected) = value else {
                return Err(AdmissionError::DenominationType {
                    node: node_index,
                    param,
                });
            };
            // A position the signature denominates and the call filled
            // with something other than an edge is already refused by the
            // kind check above, so what is left here is an edge.
            if let Some(Value::Bucket { resource, .. }) = bound.get(position)
                && *resource != expected
            {
                return Err(AdmissionError::Denomination {
                    node: node_index,
                    param,
                    expected,
                    found: *resource,
                });
            }
        }
        // A custodial gate: the holder's stored primary plus possession
        // of what it mints. The pinned shape keys the possession read by
        // exactly the claim's own expressions, so the vault key and the
        // holdings entry are the badge's own derivations.
        let custody = match gate {
            GateShape::Custody { cell: rule, claim } => {
                let eval = |expr| {
                    evaluate_expr(expr, &eval_inputs, hasher).map_err(|source| {
                        AdmissionError::Eval {
                            node: node_index,
                            source,
                        }
                    })
                };
                let badge = match eval(claim.badge())? {
                    Value::Address(badge) if badge.class() == AddressClass::Resource => badge,
                    _ => return Err(AdmissionError::MintType { node: node_index }),
                };
                let Value::Key(cell) = eval(rule)? else {
                    return Err(AdmissionError::RuleCell { node: node_index });
                };
                let holder = node.target.address();
                // An instance holder holds the badge, so presenting one
                // satisfies a rule naming the resource as well as a rule
                // naming the instance. The widening happens here, where
                // possession was verified, which is what keeps the judge
                // an equality walk rather than a subsumption rule every
                // reader of a stored rule would have to share.
                let (minted, possession) = match claim {
                    CustodyClaim::Fungible(_) => (
                        vec![Presented::Resource(badge)],
                        Possession::Vault(child_key(
                            hasher,
                            holder,
                            VAULT,
                            &[Value::Address(badge).canonical_bytes()],
                        )),
                    ),
                    CustodyClaim::Instance { id, .. } => {
                        let id = match eval(id)? {
                            Value::U64(id) => id,
                            Value::U128(id) => u64::try_from(id)
                                .map_err(|_| AdmissionError::MintType { node: node_index })?,
                            _ => return Err(AdmissionError::MintType { node: node_index }),
                        };
                        (
                            vec![Presented::Instance(badge, id), Presented::Resource(badge)],
                            Possession::Instance {
                                owner: holder,
                                holdings: holdings_collection(hasher, holder, badge),
                                id,
                            },
                        )
                    }
                };
                Some((minted, AuthorityGate::Custody { cell, possession }))
            }
            GateShape::Open | GateShape::Guarded(_) | GateShape::Rule { .. } => None,
        };
        // The gate this call is judged against, over the same inputs the
        // output types evaluate against: what the target itself names,
        // never what the caller claims.
        let authority = match gate {
            GateShape::Open => None,
            GateShape::Custody { .. } => custody.as_ref().map(|(_, gate)| gate.clone()),
            GateShape::Guarded(rule) => {
                // Every leaf, over the same inputs the output types
                // evaluate against — the shape is the declaration's and
                // only the claims are computed.
                let rule = rule.evaluate(&mut |expr| {
                    let value = evaluate_expr(expr, &eval_inputs, hasher).map_err(|source| {
                        AdmissionError::Eval {
                            node: node_index,
                            source,
                        }
                    })?;
                    Presented::of(&value).ok_or(AdmissionError::AuthorityType { node: node_index })
                })?;
                Some(AuthorityGate::Presented(rule))
            }
            GateShape::Rule { cell, role } => {
                let value = evaluate_expr(cell, &eval_inputs, hasher).map_err(|source| {
                    AdmissionError::Eval {
                        node: node_index,
                        source,
                    }
                })?;
                match value {
                    Value::Key(cell) => Some(AuthorityGate::StoredRule { cell, role }),
                    _ => return Err(AdmissionError::RuleCell { node: node_index }),
                }
            }
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
            // A bare resource address is the fungible projection; a
            // bucket states its content. Nothing else names an edge.
            node_outputs.push(match value {
                Value::Address(resource) => (resource, EdgeContent::Fungible),
                Value::Bucket { resource, content } => (resource, content),
                _ => {
                    return Err(AdmissionError::OutputType {
                        node: node_index,
                        output: slot_index,
                    });
                }
            });
        }
        // What this node mints: an authorizing method's target acting as
        // itself, a custodial method's badge, and nothing from anything
        // else.
        minted.push(match &signature.accessibility {
            Accessibility::Authorizing => vec![Presented::Identity(node.target.address())],
            Accessibility::Custodial(_) => custody.map(|(claims, _)| claims).unwrap_or_default(),
            Accessibility::Public | Accessibility::Guarded(_) | Accessibility::RoleGated(_) => {
                Vec::new()
            }
        });
        consumed.push(vec![0; node_outputs.len()]);
        outputs.push(node_outputs);
        lowered.push(Node {
            target: node.target.address(),
            method: node.method.clone(),
            inputs,
            evidence,
            authority,
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
