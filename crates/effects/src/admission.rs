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

use hyperscale_vm_types::{Address, Denomination, EffectConflict, PrincipalAddr, ResourceAddr};

use crate::dsl::{
    Declaration, EvalError, EvalInputs, evaluate_declaration, evaluate_expr, materialized_kind,
};
use crate::envelope::{YieldBinding, YieldParam};
use crate::graph::{Constraint, EvidenceRef, GraphArg, GraphNode, ManifestGraph};
use crate::hash::Hasher;
use crate::instance::{InstanceMeta, InstanceRegistry, ResolveError};
use crate::invoke::{CallArg, EdgeBound, EdgeKind, NodeCall};
use crate::manifest::{AuthorityGate, Bounds, Manifest, ManifestHash, Node, NodeInput, Possession};
use crate::metadata::{MetadataCache, PackageHash};
use crate::presented::Presented;
use crate::resource::{holdings_collection, issued_resource};
use crate::route::{FrameDeclaration, MAX_MANIFEST_NODES};
use crate::signature::{
    AbiParam, Accessibility, CustodyClaim, GateShape, MethodSignature, ParamType,
};
use crate::types::{EdgeContent, MAX_IDS_PER_EDGE, MAX_VALUE_DEPTH, Value, child_key};
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
    /// A gate's rule cell expression that does not evaluate to a key —
    /// a declaration whose shape passed and whose expression answers the
    /// wrong kind of value.
    #[error("node {node}: the rule cell expression does not evaluate to a key")]
    RuleCellType {
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
    /// A call target that does not resolve to a method.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
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
        expected: Denomination,
        /// What the routed edge actually carries.
        found: Denomination,
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
    /// A frame declaring an effect on somebody else's prefix.
    ///
    /// An object's cells are reachable by calling it, never by naming
    /// them: a package that could declare against another owner would
    /// reach that owner's state with no method of theirs in the path.
    ///
    /// Judged on the evaluated effect rather than on the expression that
    /// produced it. The publish gate refuses the expression, so an
    /// author hears about it first; this cannot be outgrown by an
    /// expression shape nobody anticipated, because an effect either
    /// carries the frame's own owner or it does not.
    #[error("node {node} declares effect {clause} on {owner:?}, which is not its own prefix")]
    ForeignDeclaration {
        /// The manifest node whose frame reached it.
        node: u32,
        /// Which of the frame's evaluated effects it is, in clause order.
        clause: u32,
        /// The prefix it reached for.
        owner: Address,
    },
    /// The capability table outgrew the index a handle is named by.
    #[error("the capability table exceeds the addressable handle space")]
    TableOverflow,
    /// An ABI argument the node's bound inputs cannot supply.
    #[error("node {node} cannot bind ABI parameter {param}: {reason}")]
    UnbindableAbiParam {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
        /// Why nothing can supply it.
        reason: String,
    },
    /// A conflict met while folding the transaction's declared effects
    /// into one set.
    #[error(transparent)]
    Conflict(#[from] EffectConflict),
    /// An expression that failed to evaluate during admission.
    #[error("evaluating node {node}")]
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
    frames: Vec<FrameDeclaration>,
    calls: Vec<NodeCall>,
    declaration: Declaration,
}

impl Admitted {
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

    /// Every evaluated frame's declaration, in node order.
    #[must_use]
    pub fn frames(&self) -> &[FrameDeclaration] {
        &self.frames
    }

    /// One lowered invocation per manifest node, in node order.
    #[must_use]
    pub fn calls(&self) -> &[NodeCall] {
        &self.calls
    }

    /// The transaction's whole declaration, both views: the folded set,
    /// and every frame's clauses concatenated in preorder — the order
    /// capability materialization builds its table in.
    #[must_use]
    pub const fn declaration(&self) -> &Declaration {
        &self.declaration
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
    admit_intents(
        &[IntentView {
            graph,
            params: &[],
            bindings: &[],
            signer: Some(composer),
        }],
        identity,
        cache,
        instances,
        hasher,
    )
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
/// shared by a direct edge and a subintent yield, so neither path can
/// drop a check the other makes. `verify` is the caller's own look at
/// the resolved resource, asked before anything is consumed.
fn bind_edge(
    outputs: &[Vec<(Denomination, EdgeContent)>],
    consumed: &mut [Vec<u32>],
    (source, output): (u32, u32),
    constraints: &[Constraint],
    param: ParamType,
    (node_index, param_index): (u32, u32),
    verify: impl FnOnce(Denomination) -> Result<(), AdmissionError>,
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

pub(crate) fn check_constraints(
    constraints: &[Constraint],
    resource: Denomination,
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
    pub signer: Option<PrincipalAddr>,
}

/// Check every intent's bindings and parameter consumption, interleave
/// the intents into one flattened node order along the yield edges, and
/// run the node-by-node admission check over that order.
pub(crate) fn admit_intents(
    intents: &[IntentView<'_>],
    identity: ManifestHash,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    let total: usize = intents.iter().map(|view| view.graph.nodes.len()).sum();
    if total > MAX_MANIFEST_NODES {
        return Err(AdmissionError::TooManyNodes);
    }

    check_bindings(intents)?;

    let (flat_of, order) = interleave(intents, total)?;

    let mut lower = Lower {
        intents,
        identity,
        cache,
        instances,
        hasher,
        flat_of: &flat_of,
        outputs: Vec::with_capacity(total),
        consumed: Vec::with_capacity(total),
        minted: Vec::with_capacity(total),
        lowered: Vec::with_capacity(total),
        frames: Vec::with_capacity(total),
        calls: Vec::with_capacity(total),
        declaration: Declaration::default(),
        table_len: 0,
    };
    for &(intent_index, local_index) in &order {
        lower.lower_node(intent_index, local_index)?;
    }
    let Lower {
        consumed,
        lowered,
        frames,
        calls,
        declaration,
        ..
    } = lower;

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

    Ok(Admitted {
        manifest: Manifest { nodes: lowered },
        identity,
        frames,
        calls,
        declaration,
    })
}

/// Bindings and parameter consumption, intent by intent: one binding
/// per declared parameter, every binding naming a real source, every
/// parameter consumed by exactly one node argument.
fn check_bindings(intents: &[IntentView<'_>]) -> Result<(), AdmissionError> {
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

    Ok(())
}

/// Deterministic interleave: repeatedly emit the lowest-indexed intent
/// whose next node has every yield dependency satisfied. Intents keep
/// their author order, so acyclicity is judged at yield granularity; a
/// stall is a cycle.
///
/// Returns the flattened position per (intent, local node) and the
/// emission order.
#[allow(clippy::type_complexity)] // the two halves of one interleave
fn interleave(
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

    Ok((flat_of, order))
}

/// The per-node lowering: everything [`admit_intents`] does with one
/// emitted node, over the accumulators the flattened order threads.
struct Lower<'a> {
    intents: &'a [IntentView<'a>],
    identity: ManifestHash,
    cache: &'a MetadataCache,
    instances: &'a InstanceRegistry,
    hasher: &'a dyn Hasher,
    /// Flattened position per (intent, local node).
    flat_of: &'a [Vec<u32>],
    /// Evaluated output projections per flattened node.
    outputs: Vec<Vec<(Denomination, EdgeContent)>>,
    /// Consumption count per output slot, per flattened node.
    consumed: Vec<Vec<u32>>,
    /// What each flattened node mints: an authorizing method's own
    /// identity, a custodial method's badge, and an empty set from
    /// anything else. A proof drawn from a node draws the whole set, so
    /// a gate that verifies more than one thing about its caller
    /// presents all of it.
    minted: Vec<Vec<Presented>>,
    lowered: Vec<Node>,
    frames: Vec<FrameDeclaration>,
    calls: Vec<NodeCall>,
    /// The transaction's whole declaration, folded frame by frame.
    declaration: Declaration,
    /// Effects logged so far across every frame: the offset the next
    /// frame's clause spans are relative to, and therefore the base of
    /// every handle position that frame's binding resolves to.
    table_len: u32,
}

impl Lower<'_> {
    fn lower_node(
        &mut self,
        intent_index: usize,
        local_index: usize,
    ) -> Result<(), AdmissionError> {
        let intent = &self.intents[intent_index];
        let node = &intent.graph.nodes[local_index];
        let node_index =
            u32::try_from(self.lowered.len()).map_err(|_| AdmissionError::TooManyNodes)?;
        let local = u32::try_from(local_index).map_err(|_| AdmissionError::TooManyNodes)?;
        let meta = self
            .instances
            .get(node.target)
            .ok_or_else(|| ResolveError::UnknownInstance(node.target.address()))?;
        self.cache
            .get(meta.package)
            .ok_or(ResolveError::UnknownPackage(meta.package))?;
        // The witness, not the record: everything behind the cache door
        // passed the composed signature check, so nothing below re-asks.
        let checked = self
            .cache
            .method(meta.package, &node.method)
            .ok_or_else(|| ResolveError::UnknownMethod {
                package: meta.package,
                method: node.method.clone(),
            })?;
        let gate = checked.gate();
        let signature = checked.signature();
        if signature.params.len() != node.args.len() {
            return Err(AdmissionError::ArityMismatch {
                node: node_index,
                expected: signature.params.len(),
                found: node.args.len(),
            });
        }

        let (bound, inputs) = self.bind_args(intent_index, local, node, signature, node_index)?;
        let evidence =
            self.resolve_evidence(intent_index, local_index, node, signature, node_index)?;

        // Evaluate this node's projections over its bound inputs.
        let eval_inputs = EvalInputs {
            self_addr: node.target.address(),
            args: &bound,
            config: &meta.config,
            node_index,
            identity: self.identity,
        };
        check_denominations(signature, &bound, &eval_inputs, self.hasher, node_index)?;
        let (claims, authority) =
            judge_gate(gate, signature, node, &eval_inputs, self.hasher, node_index)?;
        let node_outputs = project_outputs(signature, &eval_inputs, self.hasher, node_index)?;

        // The frame: this node's effect signature, evaluated over the
        // same inputs everything above evaluated over. The one place the
        // declaration comes into being.
        let frame = evaluate_declaration(&signature.effects, &eval_inputs, self.hasher).map_err(
            |source| AdmissionError::Eval {
                node: node_index,
                source,
            },
        )?;
        own_prefix_only(&frame, node.target.address(), node_index)?;
        // The frame's handles occupy the run of the capability table
        // starting here, so the offset is taken before the frame is
        // logged.
        let offset = self.table_len;
        self.calls.push(lower_call(
            node_index,
            signature,
            &Lowering {
                package: meta.package,
                declaration: &frame,
                offset,
                target: node.target.address(),
                method: &node.method,
                node_inputs: &inputs,
                node_outputs: &node_outputs,
                evidence: &evidence,
                authority: authority.as_ref(),
                inputs: &eval_inputs,
                hasher: self.hasher,
            },
        )?);
        self.table_len = offset
            .checked_add(u32::try_from(frame.ordered.len()).unwrap_or(u32::MAX))
            .ok_or(AdmissionError::TableOverflow)?;
        // The union is folded access by access, so reserve amounts two
        // clauses declared on one target sum exactly as the set
        // semantics say — and an overflow is this fold's refusal.
        for access in &frame.ordered {
            self.declaration.set.insert(access.effect)?;
            self.declaration.ordered.push(*access);
        }
        self.frames.push(FrameDeclaration {
            node: node_index,
            ordered: frame.ordered,
        });

        self.minted.push(claims);
        self.consumed.push(vec![0; node_outputs.len()]);
        self.outputs.push(node_outputs);
        self.lowered.push(Node {
            target: node.target.address(),
            method: node.method.clone(),
            inputs,
            evidence,
            authority,
        });
        Ok(())
    }

    /// Bind the node's arguments against its declared parameters: a
    /// literal for a value parameter, an edge or a yield binding for a
    /// bucket one.
    fn bind_args(
        &mut self,
        intent_index: usize,
        local: u32,
        node: &GraphNode,
        signature: &MethodSignature,
        node_index: u32,
    ) -> Result<(Vec<Value>, Vec<NodeInput>), AdmissionError> {
        let intent = &self.intents[intent_index];
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
                    let source = self.flat_of[intent_index][producer];
                    let (value, input) = bind_edge(
                        &self.outputs,
                        &mut self.consumed,
                        (source, edge.output),
                        constraints,
                        *param,
                        (node_index, param_index),
                        |_| Ok(()),
                    )?;
                    bound.push(value);
                    inputs.push(input);
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
                    if !param.is_edge() {
                        return Err(AdmissionError::ParamForValueParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    let source_intent = usize::try_from(binding.intent)
                        .map_err(|_| AdmissionError::TooManyNodes)?;
                    let producer = usize::try_from(binding.edge.producer)
                        .map_err(|_| AdmissionError::TooManyNodes)?;
                    let source = self.flat_of[source_intent][producer];
                    let intent_at =
                        u32::try_from(intent_index).expect("intents are bounded by MAX_SUBINTENTS");
                    let (value, input) = bind_edge(
                        &self.outputs,
                        &mut self.consumed,
                        (source, binding.edge.output),
                        &decl.constraints,
                        *param,
                        (node_index, param_index),
                        |resource| {
                            if resource == decl.resource {
                                Ok(())
                            } else {
                                Err(AdmissionError::YieldResourceMismatch {
                                    intent: intent_at,
                                    param: *reference,
                                })
                            }
                        },
                    )?;
                    bound.push(value);
                    inputs.push(input);
                }
            }
        }
        Ok((bound, inputs))
    }

    /// Resolve the node's presented evidence against its own intent.
    ///
    /// A proof is scoped to the intent that produced it — a signature
    /// proof to the intent whose signature, a node proof to the intent
    /// whose node — so the identities resolve against this node's own
    /// intent and no other.
    fn resolve_evidence(
        &self,
        intent_index: usize,
        local_index: usize,
        node: &GraphNode,
        signature: &MethodSignature,
        node_index: u32,
    ) -> Result<Vec<Presented>, AdmissionError> {
        let intent = &self.intents[intent_index];
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
                    evidence.push(Presented::Identity(signer.into()));
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
                        .map(|earlier| self.flat_of[intent_index][earlier])
                        .and_then(|flat| usize::try_from(flat).ok())
                        .ok_or(AdmissionError::ForwardProof {
                            node: node_index,
                            producer: *producer,
                        })?;
                    let claims = self
                        .minted
                        .get(flat)
                        .filter(|claims| !claims.is_empty())
                        .ok_or(AdmissionError::UnmintingProof {
                            node: node_index,
                            producer: *producer,
                        })?;
                    evidence.extend_from_slice(claims);
                }
            }
        }
        Ok(evidence)
    }
}

/// Judge the denominations against the bound arguments.
///
/// Judged here rather than inside the binding loop, because a
/// denomination is an expression over the *bound* arguments: one naming
/// a later position would evaluate against a parameter that loop has not
/// reached.
fn check_denominations(
    signature: &MethodSignature,
    bound: &[Value],
    eval_inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    node_index: u32,
) -> Result<(), AdmissionError> {
    for (position, denomination) in signature.denominations.iter().enumerate() {
        let Some(expr) = denomination else { continue };
        let param = u32::try_from(position).map_err(|_| AdmissionError::TooManyNodes)?;
        let value =
            evaluate_expr(expr, eval_inputs, hasher).map_err(|source| AdmissionError::Eval {
                node: node_index,
                source,
            })?;
        let Value::Address(expected) = value else {
            return Err(AdmissionError::DenominationType {
                node: node_index,
                param,
            });
        };
        let expected = Denomination::try_from(expected).map_err(|source| AdmissionError::Eval {
            node: node_index,
            source: source.into(),
        })?;
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
    Ok(())
}

/// Discriminate the gate: what this node mints, and the authority gate
/// the call is judged against — one match, so the claims and the gate
/// cannot come from two readings of the shape.
///
/// Everything evaluates over the same inputs the output types evaluate
/// against: what the target itself names, never what the caller claims.
fn judge_gate(
    gate: GateShape<'_>,
    signature: &MethodSignature,
    node: &GraphNode,
    eval_inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    node_index: u32,
) -> Result<(Vec<Presented>, Option<AuthorityGate>), AdmissionError> {
    let eval = |expr| {
        evaluate_expr(expr, eval_inputs, hasher).map_err(|source| AdmissionError::Eval {
            node: node_index,
            source,
        })
    };
    Ok(match gate {
        GateShape::Open => (Vec::new(), None),
        // A custodial gate: the holder's stored primary plus possession
        // of what it mints. The pinned shape keys the possession read by
        // exactly the claim's own expressions, so the vault key and the
        // holdings entry are the badge's own derivations.
        GateShape::Custody { cell: rule, claim } => {
            let badge = match eval(claim.badge())? {
                Value::Address(badge) => ResourceAddr::try_from(badge)
                    .map_err(|_| AdmissionError::MintType { node: node_index })?,
                _ => return Err(AdmissionError::MintType { node: node_index }),
            };
            let Value::Key(cell) = eval(rule)? else {
                return Err(AdmissionError::RuleCellType { node: node_index });
            };
            let holder = node.target.address();
            // An instance holder holds the badge, so presenting one
            // satisfies a rule naming the resource as well as a rule
            // naming the instance. The widening happens here, where
            // possession was verified, which is what keeps the judge
            // an equality walk rather than a subsumption rule every
            // reader of a stored rule would have to share.
            let (claims, possession) = match claim {
                CustodyClaim::Fungible(_) => (
                    vec![Presented::Resource(badge)],
                    Possession::Vault(child_key(
                        hasher,
                        holder,
                        VAULT,
                        &[Value::Address(badge.address()).canonical_bytes()],
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
                            holdings: holdings_collection(hasher, holder, badge.address()),
                            id,
                        },
                    )
                }
            };
            (claims, Some(AuthorityGate::Custody { cell, possession }))
        }
        GateShape::Guarded(rule) => {
            // Every leaf, over the same inputs the output types
            // evaluate against — the shape is the declaration's and
            // only the claims are computed.
            let rule = rule.map_leaves(&mut |expr| {
                let value = evaluate_expr(expr, eval_inputs, hasher).map_err(|source| {
                    AdmissionError::Eval {
                        node: node_index,
                        source,
                    }
                })?;
                Presented::of(&value).ok_or(AdmissionError::AuthorityType { node: node_index })
            })?;
            (Vec::new(), Some(AuthorityGate::Presented(rule)))
        }
        GateShape::Rule { cell, role } => {
            let Value::Key(cell) = eval(cell)? else {
                return Err(AdmissionError::RuleCellType { node: node_index });
            };
            // An authorizing method's target acts as itself; a role-gated
            // one is judged and mints nothing.
            let claims = if matches!(signature.accessibility, Accessibility::Authorizing) {
                vec![Presented::Identity(node.target)]
            } else {
                Vec::new()
            };
            (claims, Some(AuthorityGate::StoredRule { cell, role }))
        }
    })
}

/// Evaluate the node's declared output projections: the resource and
/// content of each edge it produces.
fn project_outputs(
    signature: &MethodSignature,
    eval_inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    node_index: u32,
) -> Result<Vec<(Denomination, EdgeContent)>, AdmissionError> {
    let mut node_outputs = Vec::with_capacity(signature.outputs.len());
    for (slot, expr) in signature.outputs.iter().enumerate() {
        let slot_index = u32::try_from(slot).map_err(|_| AdmissionError::TooManyNodes)?;
        let value =
            evaluate_expr(expr, eval_inputs, hasher).map_err(|source| AdmissionError::Eval {
                node: node_index,
                source,
            })?;
        // A bare resource address is the fungible projection; a
        // bucket states its content. Nothing else names an edge.
        node_outputs.push(match value {
            Value::Address(resource) => (
                Denomination::try_from(resource).map_err(|source| AdmissionError::Eval {
                    node: node_index,
                    source: source.into(),
                })?,
                EdgeContent::Fungible,
            ),
            Value::Bucket { resource, content } => (resource, content),
            _ => {
                return Err(AdmissionError::OutputType {
                    node: node_index,
                    output: slot_index,
                });
            }
        });
    }
    Ok(node_outputs)
}

/// Refuse a frame declaring an effect on a prefix that is not its own.
///
/// A declaration bounds what execution may touch; this bounds what a
/// declaration may claim. Without it the two are the same sentence read
/// twice, and a package reaches any cell it can name — a stranger's
/// balance among them — with no method's accessibility in the path,
/// because reaching for a cell is not calling the object that owns it.
///
/// Judged on the evaluated effect rather than on the expression that
/// produced it. The publish gate refuses the expression, so an author
/// hears about it first; this cannot be outgrown by an expression shape
/// nobody anticipated, because an effect either carries the frame's own
/// owner or it does not.
///
/// The nullifier a bound subintent spends is not judged here: it sits
/// under its signer's prefix, no signature declared it, and it reaches
/// the routing view as a kernel effect rather than through any frame.
fn own_prefix_only(
    declaration: &Declaration,
    instance: Address,
    node_index: u32,
) -> Result<(), AdmissionError> {
    for (position, access) in declaration.ordered.iter().enumerate() {
        let owner = access.effect.target.owner();
        if owner != instance {
            return Err(AdmissionError::ForeignDeclaration {
                node: node_index,
                clause: u32::try_from(position).unwrap_or(u32::MAX),
                owner,
            });
        }
    }
    Ok(())
}

/// What lowering one frame's binding needs beyond the frame itself.
struct Lowering<'a> {
    package: PackageHash,
    declaration: &'a Declaration,
    offset: u32,
    target: Address,
    method: &'a str,
    node_inputs: &'a [NodeInput],
    node_outputs: &'a [(Denomination, EdgeContent)],
    evidence: &'a [Presented],
    authority: Option<&'a AuthorityGate>,
    inputs: &'a EvalInputs<'a>,
    hasher: &'a dyn Hasher,
}

/// The argument a handle binding lowers to: the capability at the
/// clause's position, or the absence the guest is told about.
///
/// A span of one is the ordinary case. Zero is a clause that was guarded
/// out, and the kind travels with the argument because nothing
/// downstream can recover it — an engine reads a handle's type off the
/// capability at its rep, and there is none. More than one is a
/// `for-each`, whose width is the instance's rather than the signature's,
/// so no fixed export parameter can name it.
///
/// A span is one or zero and never more: the ABI check has already
/// refused a handle naming anything but a single access, and an access
/// contributes one entry when it is declared and none when it is not.
fn bind_handle(
    signature: &MethodSignature,
    declaration: &Declaration,
    clause: u32,
    offset: u32,
) -> Option<CallArg> {
    let index = usize::try_from(clause).ok()?;
    let (start, len) = declaration.clause_spans.get(index).copied()?;
    match len {
        1 => start.checked_add(offset).map(CallArg::Handle),
        0 => signature
            .effects
            .get(index)
            .and_then(materialized_kind)
            .map(CallArg::AbsentHandle),
        _ => None,
    }
}

/// Lower one node's ABI binding against the inputs bound to it.
///
/// Everything a binding names is settled here except a bucket's amount,
/// which does not exist until its producer runs — that stays an edge for
/// the walk to read. A handle resolves through the clause it names, which
/// is why the binding names a clause rather than a table position: a
/// guest's parameter list is a function of its own signature, and table
/// positions past the first would depend on the instance configuration a
/// `for-each` clause maps over.
fn lower_call(
    node_index: u32,
    signature: &MethodSignature,
    lowering: &Lowering<'_>,
) -> Result<NodeCall, AdmissionError> {
    let Lowering {
        package,
        declaration,
        offset,
        target,
        method,
        node_inputs,
        node_outputs,
        evidence,
        authority,
        inputs,
        hasher,
    } = *lowering;
    let mut args = Vec::with_capacity(signature.abi.len());
    for (position, binding) in signature.abi.iter().enumerate() {
        let param = u32::try_from(position).unwrap_or(u32::MAX);
        let unbindable = |reason: String| AdmissionError::UnbindableAbiParam {
            node: node_index,
            param,
            reason,
        };
        args.push(match binding {
            AbiParam::Handle(clause) => bind_handle(signature, declaration, *clause, offset)
                .ok_or_else(|| unbindable(format!("clause {clause} binds no handle")))?,
            AbiParam::Guard(clause) => {
                let taken = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| declaration.clause_taken.get(index))
                    .copied()
                    .ok_or_else(|| {
                        unbindable(format!("no effect clause {clause} in the signature"))
                    })?;
                CallArg::Bool(taken)
            }
            AbiParam::Bucket(declared) => {
                let input = usize::try_from(*declared)
                    .ok()
                    .and_then(|index| node_inputs.get(index))
                    .ok_or_else(|| unbindable(format!("no bound input {declared}")))?;
                match input {
                    NodeInput::Edge { source, output, .. } => CallArg::Bucket {
                        source: *source,
                        output: *output,
                    },
                    NodeInput::Literal(_) => {
                        return Err(unbindable(format!(
                            "input {declared} is a literal, not a value edge"
                        )));
                    }
                }
            }
            AbiParam::Issuer => CallArg::Issuer,
            AbiParam::Derived(expr) => {
                let value =
                    evaluate_expr(expr, inputs, hasher).map_err(|source| AdmissionError::Eval {
                        node: node_index,
                        source,
                    })?;
                guest_arg(&value).ok_or_else(|| {
                    unbindable(format!("a {} has no guest representation", value.kind()))
                })?
            }
        });
    }
    Ok(NodeCall {
        package,
        target,
        export: method.to_owned(),
        args,
        edges: edge_bounds(node_inputs),
        // The declared cell shape of each produced edge, from the same
        // output projections everything else evaluated against.
        outputs: node_outputs
            .iter()
            .map(|(_, content)| EdgeKind::of(content))
            .collect(),
        issues: signature
            .issues
            .as_deref()
            .map(|mark| issued_resource(hasher, target, mark).address()),
        evidence: evidence.to_vec(),
        authority: authority.cloned(),
    })
}

/// Every value edge a node consumes, with the bound its consumer signed.
///
/// Taken from the node's bound inputs rather than from its ABI binding,
/// because the two are not the same set: a method that forwards its
/// funds to a callee reads no amount, so nothing in its own ABI carries
/// the edge — and the signed bound is owed a check all the same.
fn edge_bounds(node_inputs: &[NodeInput]) -> Vec<EdgeBound> {
    node_inputs
        .iter()
        .enumerate()
        .filter_map(|(position, input)| match input {
            NodeInput::Edge {
                source,
                output,
                content,
                bounds,
                ..
            } => Some(EdgeBound {
                source: *source,
                output: *output,
                kind: EdgeKind::of(content),
                param: u32::try_from(position).unwrap_or(u32::MAX),
                bounds: *bounds,
            }),
            NodeInput::Literal(_) => None,
        })
        .collect()
}

/// A derived value's guest form. Amounts and addresses cross as their
/// canonical fixed-width bytes, and an id set crosses as the same
/// count-prefixed cell an edge carries — one framing wherever ids move.
/// The remaining compound kinds have no ABI shape and refuse rather than
/// picking an encoding the two runtimes would have to agree on
/// separately.
fn guest_arg(value: &Value) -> Option<CallArg> {
    match value {
        Value::U64(scalar) => Some(CallArg::U64(*scalar)),
        Value::U128(amount) => Some(CallArg::Bytes(amount.to_le_bytes().to_vec())),
        Value::Address(address) => Some(CallArg::Address(*address)),
        Value::Bytes(bytes) => Some(CallArg::Bytes(bytes.clone())),
        Value::List(elements) => {
            if elements.len() > MAX_IDS_PER_EDGE {
                return None;
            }
            let ids = elements
                .iter()
                .map(|element| match element {
                    Value::U64(id) => Some(*id),
                    _ => None,
                })
                .collect::<Option<Vec<u64>>>()?;
            Some(CallArg::Ids(ids))
        }
        // A judgment has no guest representation and no export takes
        // one: a selection hands over the value it chose, and a body
        // needing the comparison rebuilds it from operands that do
        // cross. A derived parameter evaluating to a judgment is refused
        // here like every other unrepresentable kind.
        Value::Key(_) | Value::Bucket { .. } | Value::Tuple(_) | Value::Bool(_) => None,
    }
}
