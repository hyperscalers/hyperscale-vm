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

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_vm_types::{
    Address, AddressClass, CallTarget, Effect, EffectConflict, EffectTarget, MAX_MANIFEST_NODES,
    Mode, Presence, PrincipalAddr, ResourceAddr,
};

use crate::dsl::{
    Clause, Declaration, DeclaredAccess, EvalBudget, EvalError, EvalInputs, PresentedGrants,
    evaluate_declaration, evaluate_expr, supports,
};
use crate::envelope::{YieldBinding, YieldParam};
use crate::graph::{Constraint, EvidenceRef, GraphArg, GraphNode, ManifestGraph};
use crate::hash::Hasher;
use crate::instance::{InstanceMeta, ResolveError};
use crate::invoke::{CallArg, EdgeBound, NodeCall};
use crate::manifest::{Bounds, JudgedLeaf, Manifest, ManifestHash, Node, NodeInput};
use crate::metadata::{PackageHash, PackageMetadata};
use crate::presented::Presented;
use crate::publish::{CheckedSignature, seals};
use crate::records::ChainRecords;
use crate::resource::{
    GrantedBehaviour, ResourceKind, granting_issued_resource, holdings_collection,
};
use crate::route::FrameDeclaration;
use crate::rule::{Holding, Rule, SealedLeaf, never};
use crate::signature::{AbiParam, MethodSignature, ParamType};
use crate::types::{EdgeContent, MAX_IDS_PER_EDGE, MAX_VALUE_DEPTH, Value, child_key};
use crate::vocabulary::{CONFIG, VAULT};

/// The bound on yield parameters one intent may declare. A wire bound.
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
    /// A movement a resource's entry grants to nobody: a debit of a
    /// soulbound credential, or a credit of value that may not come to
    /// rest.
    ///
    /// Decidable without state and without a body: whether a resource may
    /// move at all in a given direction is its entry's answer, and the
    /// resource an access is denominated in is fixed when the declaration
    /// is evaluated. So the graph is refused rather than admitted to fail
    /// later, which is what makes an obligation that must be discharged
    /// inside its transaction cost nothing when it is not.
    #[error("node {node}: {resource:?} grants {behaviour:?} to nobody, and this movement is one")]
    MovementForbidden {
        /// The offending node.
        node: u32,
        /// The resource whose entry forbids it.
        resource: ResourceAddr,
        /// Which movement the entry forbids.
        behaviour: GrantedBehaviour,
    },
    /// A movement of a resource whose address says its rules bind one,
    /// with no record presented to resolve them against.
    ///
    /// The class byte is the one fact a reader gets without a lookup, and
    /// this is what it is for: absence of a record and needing none are
    /// otherwise the same thing at the seam, so withholding the record
    /// would be a bypass anybody could take by leaving one envelope
    /// field empty. What the record costs a composer is a lookup; what it
    /// buys is that the rules a holder checked when accepting the asset
    /// are the rules every movement of it is judged against.
    #[error(
        "node {node}: {resource:?} binds a movement by its own address, and no record was \
         presented to resolve its rules"
    )]
    RecordWithheld {
        /// The offending node.
        node: u32,
        /// The resource whose record is missing.
        resource: ResourceAddr,
    },
    /// A movement rule whose bytes are not a movement rule.
    #[error("node {node}: {resource:?} has a {behaviour:?} rule that does not decode")]
    MovementRuleMalformed {
        /// The offending node.
        node: u32,
        /// The resource whose entry failed to decode.
        resource: ResourceAddr,
        /// Which entry it was.
        behaviour: GrantedBehaviour,
    },
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
    /// A record presented for a node that is not its component's seal.
    ///
    /// A component the chain has is a component whose record the chain
    /// answers with; presenting one is only ever how a component that
    /// does not exist yet is brought up.
    #[error(
        "node {node} presents a record and calls `{method}`, which is not its component's seal"
    )]
    PresentedForCall {
        /// The offending node.
        node: u32,
        /// The method it named.
        method: String,
    },
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
    ResourceKindMismatch {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
        /// The kind the parameter declares.
        expected: &'static str,
        /// The kind the producing edge carries.
        found: ResourceKind,
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
    WrongDenomination {
        /// The offending node.
        node: u32,
        /// The parameter position.
        param: u32,
        /// What the callee's declaration fixes the position to.
        expected: ResourceAddr,
        /// What the routed edge actually carries.
        found: ResourceAddr,
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
    chain: &dyn ChainRecords,
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
        chain,
        &BTreeSet::new(),
        PresentedGrants::none(),
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

pub(crate) fn check_constraints(
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
    chain: &dyn ChainRecords,
    presented: &BTreeSet<Address>,
    grants: &PresentedGrants,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    let total: usize = intents.iter().map(|view| view.graph.nodes.len()).sum();
    if total > MAX_MANIFEST_NODES {
        return Err(AdmissionError::TooManyNodes);
    }

    check_bindings(intents)?;

    let (flat_of, order) = interleave(intents, total)?;

    let budget = EvalBudget::default();
    let mut lower = Lower {
        intents,
        identity,
        chain,
        presented,
        grants,
        hasher,
        flat_of: &flat_of,
        budget: &budget,
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

/// The two records one call resolves through, held as long as the
/// signature read out of them is.
struct Resolved {
    instance: Arc<InstanceMeta>,
    package: Arc<PackageMetadata>,
}

impl Resolved {
    /// The checked signature of `method` on the resolved package.
    ///
    /// The witness is the cache's invariant: everything behind the
    /// publish door passed the composed signature check when it entered,
    /// so a record reached through here needs no second judgment.
    fn method(&self, method: &str) -> Option<CheckedSignature<'_>> {
        self.package
            .methods
            .get(method)
            .map(CheckedSignature::trusted)
    }
}

/// The per-node lowering: everything [`admit_intents`] does with one
/// emitted node, over the accumulators the flattened order threads.
struct Lower<'a> {
    intents: &'a [IntentView<'a>],
    identity: ManifestHash,
    chain: &'a dyn ChainRecords,
    /// The component addresses the envelope's own records resolve, and
    /// nothing committed does.
    ///
    /// A record may stand for exactly one call: the seal that makes its
    /// component actual. Every other target resolves from state, so a
    /// record presented beside one is a claim about a component the
    /// chain can already answer for — and admitting it would let a
    /// caller name the configuration of a component somebody else
    /// created.
    presented: &'a BTreeSet<Address>,
    grants: &'a PresentedGrants,
    hasher: &'a dyn Hasher,
    /// What admitting this envelope has spent, across every node the
    /// interleaved order holds. One meter for the tree, because a caller
    /// composes the tree and admission runs before any fee is assured.
    budget: &'a EvalBudget,
    /// Flattened position per (intent, local node).
    flat_of: &'a [Vec<u32>],
    /// Evaluated output projections per flattened node.
    outputs: Vec<Vec<(ResourceAddr, EdgeContent)>>,
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
        let resolved = self.resolve_records(node)?;
        let signature = self.resolve_signature(&resolved, node, node_index)?;
        let meta = resolved.instance.as_ref();

        let (bound, inputs) = self.bind_args(intent_index, local, node, signature, node_index)?;

        // Evaluate this node's projections over its bound inputs.
        let eval_inputs = EvalInputs {
            self_addr: node.target.address(),
            args: &bound,
            record: meta,
            node_index,
            identity: self.identity,
            grants: self.grants,
            budget: self.budget,
        };
        check_denominations(signature, &bound, &eval_inputs, self.hasher, node_index)?;
        let node_outputs = project_outputs(signature, &eval_inputs, self.hasher, node_index)?;

        // The frame: this node's effect signature, evaluated over the
        // same inputs everything above evaluated over. The one place the
        // declaration comes into being.
        let mut frame = evaluate_declaration(&signature.effects, &eval_inputs, self.hasher)
            .map_err(|source| AdmissionError::Eval {
                node: node_index,
                source,
            })?;
        own_prefix_only(&frame, node.target.address(), node_index)?;
        let fence = self.fence(node.target, &mut frame)?;
        inject_movement_rules(self.hasher, self.grants, &mut frame, node_index)?;
        // Evidence last, because what a call must present is a property
        // of the declaration this node actually evaluated rather than of
        // the clause list its signature was written with: a guard that
        // did not fire states no requirement, and neither does a granted
        // entry open to everyone. Both are conditions the frame simply
        // does not carry, and demanding a proof for one nothing will
        // consume is the refusal a caller could never satisfy.
        let evidence =
            self.resolve_evidence(intent_index, local_index, node, &frame, node_index)?;
        // The frame's handles occupy the run of the capability table
        // starting here, so the offset is taken before the frame is
        // logged.
        let offset = self.table_len;
        // A frame's conditions split by where each is judged, and nothing
        // declares which: a rule answerable from committed state joins
        // the union declaration and is judged at materialization, beside
        // the presence a write requires; one whose leaves reach the
        // call's evidence rides the node's call.
        let mut requires = Vec::new();
        for rule in &frame.conditions {
            if rule.reads_state_only() {
                self.declaration.conditions.push(rule.clone());
            } else {
                requires.push(rule.clone());
            }
        }
        if let Some(condition) = fence {
            self.declaration.conditions.push(condition);
        }
        self.calls.push(lower_call(
            node_index,
            signature,
            Lowering {
                package: meta.package,
                declaration: &frame,
                offset,
                target: node.target.address(),
                method: &node.method,
                node_inputs: &inputs,
                node_outputs: &node_outputs,
                evidence: &evidence,
                requires,
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
        // What this node mints is read off its declared clauses, the
        // widening already applied where the evaluation resolved them.
        self.minted.push(frame.mints);
        self.frames.push(FrameDeclaration {
            node: node_index,
            ordered: frame.ordered,
        });
        self.consumed.push(vec![0; node_outputs.len()]);
        self.outputs.push(node_outputs);
        self.lowered.push(Node {
            target: node.target.address(),
            method: node.method.clone(),
            inputs,
            evidence,
        });
        Ok(())
    }

    /// The two records a node's call resolves through: the instance its
    /// target names, and the package that instance runs.
    ///
    /// Held as shared handles rather than borrowed out of a collection,
    /// because the chain's records need not be a map this can point
    /// into. The caller keeps the pair alive for as long as it reads the
    /// signature out of it.
    fn resolve_records(&self, node: &GraphNode) -> Result<Resolved, AdmissionError> {
        let instance = self
            .chain
            .instance(node.target)
            .ok_or_else(|| ResolveError::UnknownInstance(node.target.address()))?;
        let package = self
            .chain
            .package(instance.package)
            .ok_or(ResolveError::UnknownPackage(instance.package))?;
        Ok(Resolved { instance, package })
    }

    /// The signature a node's call names, held to what this envelope may
    /// say about it.
    ///
    /// The last link of the chain from an address through its record and
    /// package — and then two judgments the signature makes possible:
    /// whether a record the envelope carried may stand for this call at
    /// all, and whether the arguments match what the method declares.
    fn resolve_signature<'r>(
        &self,
        resolved: &'r Resolved,
        node: &GraphNode,
        node_index: u32,
    ) -> Result<&'r MethodSignature, AdmissionError> {
        // The witness, not the record: everything behind the cache door
        // passed the composed signature check, so nothing below re-asks.
        let checked = resolved
            .method(&node.method)
            .ok_or_else(|| ResolveError::UnknownMethod {
                package: resolved.instance.package,
                method: node.method.clone(),
            })?;
        let signature = checked.signature();
        // A record the envelope carried stands for the seal of the
        // component it derives and nothing else. Every other target
        // answers from committed state, so a record beside one would be
        // a caller stating the configuration of a component the chain
        // holds its own answer for — and the two need never agree.
        if self.presented.contains(&node.target.address()) && !seals(signature) {
            return Err(AdmissionError::PresentedForCall {
                node: node_index,
                method: node.method.clone(),
            });
        }
        if signature.params.len() != node.args.len() {
            return Err(AdmissionError::ArityMismatch {
                node: node_index,
                expected: signature.params.len(),
                found: node.args.len(),
            });
        }
        Ok(signature)
    }

    /// The instantiation fence for a node's target: the read of its
    /// configuration leaf, appended to `frame`, and the presence the
    /// judging shard holds it to.
    ///
    /// The protocol's own term rather than the package's. Whether a
    /// creation finished is a question about the target's address class
    /// — a component derives from a record and has one to finish, a
    /// principal derives from a key and has none — so it is answered
    /// where the class is known and not by every method of every
    /// package restating it. A package cannot omit what it does not
    /// write, which is what makes the fence universal over hand-written
    /// declarations and derived ones alike.
    ///
    /// The read is appended, so every clause span the signature's own
    /// ABI bindings name keeps the position it had.
    ///
    /// A node that writes the leaf is the seal itself, and takes no
    /// presence: its own `Absent` door is what it declares, and the
    /// publish gate admits no other write at the slot.
    fn fence(
        &self,
        target: CallTarget,
        frame: &mut Declaration,
    ) -> Result<Option<Rule<JudgedLeaf>>, AdmissionError> {
        let CallTarget::Component(address) = target else {
            return Ok(None);
        };
        let leaf = EffectTarget::Point(child_key(self.hasher, address, CONFIG, &[]));
        let grants = frame.ordered.iter().any(|access| {
            access.effect.target == leaf && matches!(access.effect.mode, Mode::Write)
        });
        if grants {
            return Ok(None);
        }
        let effect = Effect {
            target: leaf,
            mode: Mode::Read,
        };
        frame.set.insert(effect)?;
        frame.ordered.push(DeclaredAccess {
            effect,
            holds: None,
        });
        Ok(Some(Rule::Require(JudgedLeaf::Presence {
            target: leaf,
            expect: Presence::Present,
        })))
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
        frame: &Declaration,
        node_index: u32,
    ) -> Result<Vec<Presented>, AdmissionError> {
        let intent = &self.intents[intent_index];
        // Every authority condition the evaluated frame carries, which is
        // what a proof presented here could satisfy — an authored gate,
        // or a requirement admission injected onto the frame.
        let required: Vec<&Rule<JudgedLeaf>> = frame
            .conditions
            .iter()
            .filter(|rule| !rule.reads_state_only())
            .collect();
        // Evidence presence is a property of what this call requires: a
        // guarded or authorizing call presents something, a public one
        // presents nothing. Whether what it presents satisfies the
        // target's rule is the target's own business, answered where the
        // target's state is.
        if !required.is_empty() {
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
                    let reads_a_rule = required.iter().any(|rule| {
                        rule.leaves()
                            .any(|leaf| matches!(leaf, JudgedLeaf::Stored { .. }))
                    });
                    if !reads_a_rule {
                        return Err(AdmissionError::SignatureForGuarded { node: node_index });
                    }
                    let signer = intent
                        .signer
                        .ok_or(AdmissionError::UnsignedEvidence { node: node_index })?;
                    evidence.push(Presented::of_subject(signer));
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
        let expected = ResourceAddr::try_from(expected).map_err(|source| AdmissionError::Eval {
            node: node_index,
            source: source.into(),
        })?;
        // A position the signature denominates and the call filled
        // with something other than an edge is already refused by the
        // kind check above, so what is left here is an edge.
        if let Some(Value::Bucket { resource, .. }) = bound.get(position)
            && *resource != expected
        {
            return Err(AdmissionError::WrongDenomination {
                node: node_index,
                param,
                expected,
                found: *resource,
            });
        }
    }
    Ok(())
}

/// Evaluate the node's declared output projections: the resource and
/// content of each edge it produces.
fn project_outputs(
    signature: &MethodSignature,
    eval_inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    node_index: u32,
) -> Result<Vec<(ResourceAddr, EdgeContent)>, AdmissionError> {
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
                ResourceAddr::try_from(resource).map_err(|source| AdmissionError::Eval {
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

/// Inject the movement requirements this frame's declared accesses earn.
///
/// A package will not declare a rule it does not want, so the requirement
/// comes from here rather than from the signature — which is what makes
/// omission inexpressible: a component's vault is fenced exactly as an
/// account's is, and neither package wrote a word about it.
///
/// Appended to the frame's own conditions, so everything downstream reads
/// them the way it reads an authored one, and placed where its leaves
/// send it — which for a movement rule is always materialization, since
/// every leaf it holds reads the store.
///
/// One requirement per (owner, resource, behaviour) however many accesses
/// name it, since a rule asked twice is one question. Each holding
/// resolves against the access's own owner, and the read it names is
/// appended so the state is provisioned wherever the call runs — the
/// owner is the frame's own instance, which `own_prefix_only` has already
/// held every access to, so nothing here adds a participant.
fn inject_movement_rules(
    hasher: &dyn Hasher,
    grants: &PresentedGrants,
    frame: &mut Declaration,
    node_index: u32,
) -> Result<(), AdmissionError> {
    // Which requirements this frame earns, before any is built: an access
    // whose mode reaches both directions earns both, and only a
    // reservation carries its own.
    let mut wanted: Vec<(Address, ResourceAddr, GrantedBehaviour)> = Vec::new();
    for access in &frame.ordered {
        let Some(resource) = access.holds else {
            continue;
        };
        let owner = access.effect.target.owner();
        let behaviours: &[GrantedBehaviour] = match access.effect.mode {
            // The two that carry their direction are judged on the
            // movement they make and nothing else.
            Mode::Reserve { .. } => &[GrantedBehaviour::Withdraw],
            Mode::Credit => &[GrantedBehaviour::Deposit],
            // The rest reach both ways through one access, so both are
            // asked. That over-binds — a holder permitted to send is
            // asked for the receiving credential too — which is why a
            // method that only moves one way says so and is judged on
            // that alone.
            Mode::Delta | Mode::Write => &[GrantedBehaviour::Withdraw, GrantedBehaviour::Deposit],
            Mode::Read => continue,
        };
        for behaviour in behaviours {
            let entry = (owner, resource, *behaviour);
            if !wanted.contains(&entry) {
                wanted.push(entry);
            }
        }
    }

    for (owner, resource, behaviour) in wanted {
        // A resource whose record was not presented grants nothing here,
        // and what tells that apart from a bypass is the address itself:
        // one whose entries can stop a movement carries the class that
        // says so, and moving it with nothing to resolve is refused.
        let Some(rules) = grants.rules(resource) else {
            if resource.address().class() == AddressClass::Restricted {
                return Err(AdmissionError::RecordWithheld {
                    node: node_index,
                    resource,
                });
            }
            continue;
        };
        let Some(sealed) = rules.get(behaviour) else {
            continue;
        };
        let rule = sealed
            .decode()
            .map_err(|_| AdmissionError::MovementRuleMalformed {
                node: node_index,
                resource,
                behaviour,
            })?;
        // Nobody may: decidable from the entry, without state and without
        // a body, so the graph is refused rather than admitted to fail
        // later.
        if rule == never() {
            return Err(AdmissionError::MovementForbidden {
                node: node_index,
                resource,
                behaviour,
            });
        }
        // The sealed rule is about the mover, and this is where the mover
        // is known: every holding it names resolves to a leaf under the
        // access's own owner, and the read is appended so the leaf is
        // provisioned wherever the call runs.
        let resolved = rule.map_leaves(&mut |leaf| match leaf {
            SealedLeaf::Held { badge, holding } => {
                let target = holding_target(hasher, owner, *badge, *holding);
                declare_read(frame, target);
                Ok(JudgedLeaf::Presence {
                    target,
                    expect: Presence::Present,
                })
            }
            // A movement entry's rule reads holdings alone, refused
            // at the seal otherwise, so nothing else can arrive.
            SealedLeaf::Claim(_) => Err(AdmissionError::MovementRuleMalformed {
                node: node_index,
                resource,
                behaviour,
            }),
        })?;
        // Two entries can seal one rule — a resource putting both
        // directions on one register does — and a rule asked twice is
        // one question wherever the duplicate came from.
        if !frame.conditions.contains(&resolved) {
            frame.conditions.push(resolved);
        }
    }
    Ok(())
}

/// What `owner`'s holding of `badge` occupies, in the shape the sealed
/// leaf asks about.
///
/// A balance is the one point cell keyed by what it holds, and a balance
/// reaching zero deletes its leaf — so presence and a nonzero holding
/// are the same fact, asked once. Instances are entries of the holder's
/// collection for the badge, so holding one is that entry and holding
/// any is the interval holding something: one seek either way, and the
/// interval is what a holder pays for the question spanning the id
/// space.
fn holding_target(
    hasher: &dyn Hasher,
    owner: Address,
    badge: ResourceAddr,
    holding: Holding,
) -> EffectTarget {
    match holding {
        Holding::Balance => EffectTarget::Point(child_key(
            hasher,
            owner,
            VAULT,
            &[Value::Address(badge.address()).canonical_bytes()],
        )),
        // An instance's id is its order key and an id is a `u64`, so the
        // interval that can hold one is the interval declared.
        Holding::AnyInstance => EffectTarget::Range {
            owner,
            collection: holdings_collection(hasher, owner, badge),
            lo: 0,
            hi: u128::from(u64::MAX),
            // One entry answers whether any is there, whatever else the
            // interval holds.
            cap: 1,
        },
        Holding::Instance(id) => EffectTarget::Entry {
            owner,
            collection: holdings_collection(hasher, owner, badge),
            order: u128::from(id),
        },
    }
}

/// Append a read of `target` to the frame, so a condition over it is
/// provisioned wherever this call runs.
fn declare_read(frame: &mut Declaration, target: EffectTarget) {
    let effect = Effect {
        target,
        mode: Mode::Read,
    };
    // A repeated insert is the same effect: the declaration already
    // carries it, and the condition beside it asks the same question.
    if frame.set.insert(effect).is_ok() {
        frame.ordered.push(DeclaredAccess {
            effect,
            holds: None,
        });
    }
}

/// What lowering one frame's binding needs beyond the frame itself.
struct Lowering<'a> {
    package: PackageHash,
    declaration: &'a Declaration,
    offset: u32,
    target: Address,
    method: &'a str,
    node_inputs: &'a [NodeInput],
    node_outputs: &'a [(ResourceAddr, EdgeContent)],
    evidence: &'a [Presented],
    requires: Vec<Rule<JudgedLeaf>>,
    inputs: &'a EvalInputs<'a>,
    hasher: &'a dyn Hasher,
}

/// The argument a run binding lowers to: what one `for-each` site
/// declared, one entry per element of the list its loop mapped over.
///
/// Every entry resolves through the map the evaluation recorded, so
/// nothing here computes a position — what the walk did is what the run
/// covers, and an expansion the site's guard did not fire for is an
/// absence rather than a gap.
fn bind_run(
    signature: &MethodSignature,
    declaration: &Declaration,
    clause: u32,
    site: u32,
    offset: u32,
) -> Result<CallArg, String> {
    let entries = declaration
        .run(clause, site)
        .ok_or_else(|| format!("clause {clause} has no site {site} to run"))?;
    let backed = usize::try_from(clause)
        .ok()
        .and_then(|index| signature.effects.get(index))
        .and_then(|clause| match clause {
            Clause::ForEach { body, .. } => {
                usize::try_from(site).ok().and_then(|index| body.get(index))
            }
            _ => None,
        })
        .is_some_and(supports);
    if !backed {
        return Err(format!(
            "site {site} of clause {clause} materializes nothing"
        ));
    }
    let entries = entries
        .iter()
        .map(|entry| {
            entry.map_or(Ok(None), |position| {
                position
                    .checked_add(offset)
                    .map(Some)
                    .ok_or_else(|| "the capability table overflowed".to_owned())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CallArg::Run { entries })
}

/// The argument a handle binding lowers to: the capability at the
/// clause's position, or the absence the guest is told about.
///
/// A span of one is the ordinary case. Zero is a clause that was guarded
/// out, which the guest is handed all the same — an export's parameter
/// list is a function of its signature and cannot lose a parameter to a
/// branch. More than one is a `for-each`, whose width is the instance's
/// rather than the signature's, so no fixed export parameter can name
/// it.
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
            .is_some_and(supports)
            .then_some(CallArg::AbsentHandle),
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
    lowering: Lowering<'_>,
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
        requires,
        inputs,
        hasher,
    } = lowering;
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
            AbiParam::Run { clause, site } => {
                bind_run(signature, declaration, *clause, *site, offset).map_err(&unbindable)?
            }
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
        // The declared content of each produced edge, from the same
        // output projections everything else evaluated against.
        outputs: node_outputs
            .iter()
            .map(|(_, content)| content.clone())
            .collect(),
        issues: signature
            .issues
            .as_ref()
            .map(|issuance| -> Result<_, AdmissionError> {
                // The rules the mark grants ride the grant's own address,
                // so what a body mints is what a gate naming the same
                // resource resolves to.
                let rules = issuance
                    .grants
                    .resolve(hasher, target, &inputs.record.config)
                    .map_err(|source| AdmissionError::Eval {
                        node: node_index,
                        source: source.into(),
                    })?;
                Ok((
                    granting_issued_resource(hasher, target, issuance.kind, &rules, &issuance.mark),
                    issuance.kind,
                ))
            })
            .transpose()?,
        evidence: evidence.to_vec(),
        requires,
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
                bounds,
                ..
            } => Some(EdgeBound {
                source: *source,
                output: *output,
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
        // The same framing an amount crosses in, at twice the width: a
        // stored rate is a number the guest decodes, not a shape the
        // boundary knows about.
        Value::U256(scaled) => Some(CallArg::Bytes(scaled.to_vec())),
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
        // A judgment crosses as the flag a guarded clause's verdict
        // already crosses as. Most comparisons never reach here — a body
        // needing one rebuilds it from operands that cross, and a
        // selection hands over the value it chose — but a question only
        // the evaluator can answer, such as whether a configured table
        // holds a key, has no operands the guest holds.
        Value::Bool(judgment) => Some(CallArg::Bool(*judgment)),
        Value::Key(_) | Value::Bucket { .. } | Value::Tuple(_) => None,
    }
}
