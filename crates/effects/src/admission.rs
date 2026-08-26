//! Admission: the judgement that turns a signed form into a routing
//! manifest.
//!
//! One checker serves both signed forms. A bare graph is the degenerate
//! envelope — a single intent with no sockets and no subintents — and a
//! composed tree is several intents joined through the sockets they
//! declare, each carrying a value edge or a proof. So [`admit_intents`]
//! takes a slice of [`IntentView`] and everything below it is
//! shape-agnostic: bindings and socket consumption per intent, a
//! deterministic interleave over the sockets each node reaches, then one
//! pass over the flattened node order checking arity, kinds, linearity,
//! and constraints.
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

use crate::auth::RuleBytes;
use crate::dsl::{
    Clause, Condition, Declaration, DeclaredAccess, EvalBudget, EvalError, EvalInputs,
    PresentedGrants, Reach, evaluate_declaration, evaluate_expr, supports,
};
use crate::envelope::{Binding, Socket};
use crate::graph::{Constraint, EvidenceRef, GraphArg, GraphNode, ManifestGraph};
use crate::hash::Hasher;
use crate::instance::{InstanceMeta, ResolveError};
use crate::invoke::{CallArg, EdgeBound, IssuanceGrant, NodeCall};
use crate::manifest::{Bounds, Judged, JudgedLeaf, Manifest, ManifestHash, Node, NodeInput};
use crate::metadata::{PackageHash, PackageMetadata};
use crate::presented::Presented;
use crate::publish::{CheckedSignature, seals};
use crate::records::ChainRecords;
use crate::resource::{
    GrantedBehaviour, ResourceKind, granting_issued_resource, holdings_collection,
    resource_record_key,
};
use crate::route::FrameDeclaration;
use crate::rule::{Holding, Rule, SealedLeaf, StoredRule, never};
use crate::signature::{AbiParam, Issued, MethodSignature, ParamType};
use crate::types::{EdgeContent, MAX_IDS_PER_EDGE, MAX_VALUE_DEPTH, Value, child_key};
use crate::vocabulary::{CONFIG, HALT, VAULT};

/// The bound on sockets one intent may declare. A wire bound.
///
/// An intent binds one edge per parameter, so this bounds the binding
/// vector too — which is what makes every parameter position expressible
/// as a `u32` index by construction rather than by hope.
pub const MAX_SOCKETS: usize = 32;

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
    /// A frame exercising an authority nothing admits: the resource
    /// grants no entry for the behaviour, or grants one whose record
    /// this transaction did not present.
    ///
    /// One verdict for issuing, destroying and reaching, because it is
    /// one sentence in all three — **absence withholds**. Where the
    /// entry comes from differs and the verdict does not: an issuance
    /// rule is read off the declaration that derives the address, and a
    /// destruction's or a reach's off the record a caller presented, so
    /// withholding the record and granting nothing say the same thing.
    /// Both are the safe direction for an authority; what a missing
    /// record would open is a movement, and that is
    /// [`RecordWithheld`](Self::RecordWithheld)'s to refuse.
    ///
    /// An issuance also meets this at publish, where the author wrote
    /// the pair — so reaching it here is metadata that never met that
    /// door. Judged again because absence is the whole spelling of
    /// nobody-may: an entry that said it outright is refused at the
    /// seal.
    #[error(
        "node {node}: nothing admits {behaviour:?} of {resource:?} — no such entry, or no \
         record presented to resolve one"
    )]
    Unadmitted {
        /// The offending node.
        node: u32,
        /// The resource whose entry would have admitted it.
        resource: ResourceAddr,
        /// The authority exercised.
        behaviour: GrantedBehaviour,
    },
    /// A parameter declared destroyed that carries no value edge.
    #[error("node {node}: parameter {param} is destroyed and carries no value edge")]
    DestroysNoEdge {
        /// The offending node.
        node: u32,
        /// The offending parameter.
        param: u32,
    },
    /// An entry whose bytes are not the rule its behaviour admits.
    ///
    /// One verdict for every entry, because the bytes fail the same way
    /// wherever they came from and the message could say nothing else.
    ///
    /// Reachable rather than defensive, and the record is why. A
    /// resource's own declaration meets the seal, which refuses an
    /// actor question's rule that reads a holding — but a presented
    /// record is a caller's, and a self-consistent one carrying such a
    /// rule resolves at the address it derives. It fails closed here.
    #[error("node {node}: {resource:?} has a {behaviour:?} entry that does not decode")]
    EntryMalformed {
        /// The offending node.
        node: u32,
        /// The resource whose entry it is.
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
    /// An intent whose bindings do not match its sockets.
    #[error("intent {intent} declares {expected} parameters, binds {found}")]
    BindingArity {
        /// The intent: `0` is the root, `i + 1` is subintent `i`.
        intent: u32,
        /// How many sockets it declared.
        expected: usize,
        /// How many bindings the composition supplied.
        found: usize,
    },
    /// A binding naming an intent or node that does not exist.
    #[error("intent {intent} socket {socket} is filled from nowhere")]
    UnknownBinding {
        /// The consuming intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// A value socket filled with an edge carrying some other resource
    /// than the shape it was declared with.
    #[error("intent {intent} socket {socket}: what fills it carries another resource")]
    SocketResourceMismatch {
        /// The consuming intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// A socket no node of the declaring graph reaches, so nothing
    /// would consume what the composition puts in it.
    #[error("intent {intent} socket {socket} is never reached")]
    UnreachedSocket {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// A value socket consumed by more than one node argument. An
    /// authority socket is not held to it: a claim presented twice says
    /// nothing presenting it once does not.
    #[error("intent {intent} socket {socket} is consumed twice")]
    SocketReused {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// A socket reference past what the intent declared — in a bare
    /// graph, any socket reference at all.
    #[error("node {node} references socket {socket}, which is not declared")]
    UnknownSocket {
        /// The consuming node.
        node: u32,
        /// The socket it named.
        socket: u32,
    },
    /// Sockets admitting no execution order: intents wait on each other
    /// in a cycle, through their arguments or through their evidence.
    #[error("the envelope's sockets admit no execution order")]
    CyclicSockets,
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
    /// A movement entry a total frame cannot be held to.
    ///
    /// The mark says a caller may commit without waiting to hear back,
    /// so every verdict the frame carries has to land before any leg
    /// does. An entry asking both what the mover holds and what the call
    /// presented is answerable in neither earlier stage alone, so it is
    /// the declaring node's own walk that would reach it — after a
    /// caller may already have committed.
    #[error(
        "node {node} is total and moves {resource:?}, whose {behaviour:?} entry asks both what \
         the mover holds and what the call presented"
    )]
    MovementUnanswerable {
        /// The offending node.
        node: u32,
        /// The resource whose entry it is.
        resource: ResourceAddr,
        /// The behaviour the entry governs.
        behaviour: GrantedBehaviour,
    },
    /// A proof socket bound to a node that does not mint the claim the
    /// declaration named.
    ///
    /// What makes a socket worth signing: the signer says which
    /// authority they are asking for, and a composition that supplies
    /// some other one is refused rather than quietly presenting it.
    #[error("node {node} presents socket {socket}, which is filled by no such claim")]
    SocketClaimMismatch {
        /// The presenting node.
        node: u32,
        /// The socket it presented.
        socket: u32,
    },
    /// Evidence that does not satisfy what the node must present.
    ///
    /// Reached here rather than in the walk for every rule this stage
    /// can decide — a claim leaf reads the node's own signed evidence
    /// and nothing else — so a wallet hears it before signing and a
    /// total leg never carries the verdict into its own execution.
    #[error("node {node} presents evidence that does not satisfy what it must")]
    EvidenceUnsatisfied {
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
    /// An argument count differing from the sockets.
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
    /// A frame reaching under an authority and naming its own prefix.
    ///
    /// A reaching access carries no injected movement requirement of any
    /// kind, because the party reached is by construction the one every
    /// requirement would fire against. Where that party is the frame
    /// itself the exemption has nothing to justify it: the access does
    /// what a plain access does and is judged by less, so a component
    /// would be exempt from the entries of the very resources it holds.
    ///
    /// Refused at publish where the owner is spelled `SelfAddr`, and
    /// here for every other spelling — which is all of them that matter,
    /// since a reach names its owner by argument and publish sees an
    /// expression rather than an address.
    #[error("node {node} reaches under an authority at effect {clause} and names its own prefix")]
    ReachesItself {
        /// The manifest node whose frame reached it.
        node: u32,
        /// Which of the frame's evaluated effects it is, in clause order.
        clause: u32,
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
    /// An intent declaring more sockets than [`MAX_SOCKETS`].
    #[error("intent {intent} declares more than {MAX_SOCKETS} sockets")]
    TooManySockets {
        /// The declaring intent.
        intent: u32,
    },
    /// A socket bound to a method parameter that is not a bucket.
    #[error("node {node} argument {param}: a socket cannot bind a value parameter")]
    SocketForValueParam {
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
    injected: Vec<Vec<Injected>>,
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

    /// What the protocol put on each frame, in node order beside
    /// [`frames`](Self::frames).
    ///
    /// Kept rather than dropped because the rule alone cannot say who
    /// asked: it names a key, and a key is a hash that inverts to
    /// nothing. Local to whoever admitted, never signed and never
    /// routed — the shards judge the rules, and only a reader needs the
    /// entry behind one.
    #[must_use]
    pub fn injected(&self) -> &[Vec<Injected>] {
        &self.injected
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
    admit_presenting(graph, composer, chain, PresentedGrants::none(), hasher)
}

/// The same, over resource records the composer presents.
///
/// A bare graph presents nothing, which is what every ungranted flow
/// needs; a graph reaching a resource whose rules govern needs the
/// record those rules derive, because the address is the hash of them
/// and re-derivation is what makes a presented record trustworthy.
///
/// # Errors
///
/// [`AdmissionError`] on the same terms as [`admit`].
pub fn admit_presenting(
    graph: &ManifestGraph,
    composer: PrincipalAddr,
    chain: &dyn ChainRecords,
    grants: &PresentedGrants,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    check_value_depth(graph)?;
    let identity = graph.hash(hasher);
    admit_intents(
        &[IntentView {
            graph,
            sockets: &[],
            bindings: &[],
            signer: Some(composer),
        }],
        identity,
        chain,
        &BTreeSet::new(),
        grants,
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
/// shared by a direct edge and one filling a socket, so neither path can
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
    pub sockets: &'a [Socket],
    pub bindings: &'a [Binding],
    /// Whose signature this intent carries, and so whose identity its
    /// proof names. A bare graph is unsigned and produces none.
    pub signer: Option<PrincipalAddr>,
}

/// Check every intent's bindings and socket consumption, interleave the
/// intents into one flattened node order over the sockets they declare,
/// and run the node-by-node admission check over that order.
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
        injected: Vec::with_capacity(total),
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
        injected,
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
        injected,
        calls,
        declaration,
    })
}

/// Bindings and parameter consumption, intent by intent: one binding
/// per socket, every binding naming a real source, every
/// parameter consumed by exactly one node argument.
fn check_bindings(intents: &[IntentView<'_>]) -> Result<(), AdmissionError> {
    for (index, intent) in intents.iter().enumerate() {
        if intent.sockets.len() > MAX_SOCKETS {
            return Err(AdmissionError::TooManySockets {
                intent: u32::try_from(index).expect("intents are bounded by MAX_SUBINTENTS"),
            });
        }
        let intent_index = u32::try_from(index).expect("intents are bounded by MAX_SUBINTENTS");
        if intent.bindings.len() != intent.sockets.len() {
            return Err(AdmissionError::BindingArity {
                intent: intent_index,
                expected: intent.sockets.len(),
                found: intent.bindings.len(),
            });
        }
        for (position, binding) in intent.bindings.iter().enumerate() {
            let socket = u32::try_from(position).expect("bounded by MAX_SOCKETS");
            let source = usize::try_from(binding.intent())
                .ok()
                .and_then(|source| intents.get(source));
            let producer = usize::try_from(binding.producer()).unwrap_or(usize::MAX);
            if source.is_none_or(|source| producer >= source.graph.nodes.len()) {
                return Err(AdmissionError::UnknownBinding {
                    intent: intent_index,
                    socket,
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
        for (position, count) in uses.iter().enumerate() {
            let socket = u32::try_from(position).expect("bounded by MAX_SOCKETS");
            if *count == 0 {
                return Err(AdmissionError::UnreachedSocket {
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
            // Every socket this node reaches, whichever way it reaches
            // one: an argument consuming the edge that fills it, and
            // evidence presenting the proof that does. Both are
            // dependencies on another intent's node, and a proof left
            // out of this scan would let a node present a claim minted
            // after it ran.
            for socket in node.sockets() {
                // An out-of-range socket carries no dependency; the
                // node check below rejects it.
                let Some(binding) = usize::try_from(socket)
                    .ok()
                    .and_then(|position| intent.bindings.get(position))
                else {
                    continue;
                };
                let source = usize::try_from(binding.intent()).unwrap_or(usize::MAX);
                let producer = usize::try_from(binding.producer()).unwrap_or(usize::MAX);
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
    /// What the protocol put on each frame, beside it.
    injected: Vec<Vec<Injected>>,
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
        judge_prefixes(&frame, node.target.address(), node_index)?;
        let fence = self.fence(node.target, &mut frame)?;
        let (issues, injected) = self.inject(
            signature,
            node.target.address(),
            &meta.config,
            &inputs,
            &mut frame,
            node_index,
        )?;
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
        self.split_conditions(&frame, node_index, &mut requires);
        if let Some(rule) = fence {
            self.declaration.conditions.push(Condition {
                rule,
                node: Some(node_index),
            });
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
                issues,
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
        self.injected.push(injected);
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
            access.effect.target == leaf && matches!(access.effect.mode, Mode::Write { .. })
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
            reach: None,
        });
        Ok(Some(Rule::Require(JudgedLeaf::Presence {
            target: leaf,
            expect: Presence::Present,
        })))
    }

    /// Bind the node's arguments against the signature's parameters: a
    /// literal for a value parameter, and for a bucket one either an
    /// edge of this graph or the socket some other intent fills.
    fn bind_args(
        &mut self,
        intent_index: usize,
        local: u32,
        node: &GraphNode,
        signature: &MethodSignature,
        node_index: u32,
    ) -> Result<(Vec<Value>, Vec<NodeInput>), AdmissionError> {
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
                GraphArg::Socket(reference) => {
                    let (value, input) = self.bind_socket(
                        intent_index,
                        *reference,
                        *param,
                        (node_index, param_index),
                    )?;
                    bound.push(value);
                    inputs.push(input);
                }
            }
        }
        Ok((bound, inputs))
    }

    /// Every requirement the protocol puts on `frame`, appended to its
    /// own conditions and answered whole beside them.
    ///
    /// None of it is declared. A package will not write a rule it does
    /// not want, so each of these comes from the resource rather than
    /// from the signature — which is what makes omission inexpressible —
    /// and each is returned carrying the entry that demanded it, because
    /// the rule alone says what must hold and cannot say who asked.
    ///
    /// A rule asked twice is one question wherever the duplicate came
    /// from: a resource putting both directions of a movement on one
    /// register asks it twice, and the frame carries it once.
    fn inject(
        &self,
        signature: &MethodSignature,
        target: Address,
        config: &[Value],
        inputs: &[NodeInput],
        frame: &mut Declaration,
        node_index: u32,
    ) -> Result<(Vec<IssuanceGrant>, Vec<Injected>), AdmissionError> {
        // The reach's own entry before the movement entries, because a
        // reaching access earns none of the latter and a reader should
        // meet the authority that admitted it first.
        let mut injected = inject_reach_rules(self.grants, frame, target, node_index)?;
        injected.extend(inject_movement_rules(
            self.hasher,
            self.grants,
            frame,
            signature.totality.is_total(),
            node_index,
        )?);
        // Issuance is an actor question like any other, so its entry
        // joins the frame's conditions and computed placement routes it
        // to the call. Before evidence, because what a caller must
        // present is a property of the conditions the frame carries.
        let (mut issues, issuance) =
            inject_issuance_rules(self.hasher, signature, target, config, frame, node_index)?;
        injected.extend(issuance);
        // Appended after them, so the index a body passes to a mint is
        // the position its own declaration fixed: a destruction names no
        // index, since the bucket carries the resource it holds.
        let (destroyed, destruction) =
            inject_destruction_rules(self.grants, signature, inputs, target, node_index)?;
        issues.extend(destroyed);
        injected.extend(destruction);
        for requirement in &injected {
            if !frame.required().any(|rule| *rule == requirement.rule) {
                frame
                    .conditions
                    .push(Condition::declared(requirement.rule.clone()));
            }
        }
        Ok((issues, injected))
    }

    /// Split a frame's conditions by where each is judged.
    ///
    /// One answerable from committed state alone joins the union
    /// declaration and is judged at materialization, beside the presence
    /// a write requires; every other rides the node's call, where the
    /// evidence is. Nothing declares which.
    fn split_conditions(
        &mut self,
        frame: &Declaration,
        node_index: u32,
        requires: &mut Vec<Rule<JudgedLeaf>>,
    ) {
        for condition in &frame.conditions {
            if condition.rule.judged() == Judged::AtMaterialization {
                // Stamped here rather than at the frame, because this is
                // where the number starts meaning something: a frame's
                // own conditions are one node's, and the union's are
                // every node's in one list.
                self.declaration.conditions.push(Condition {
                    rule: condition.rule.clone(),
                    node: Some(node_index),
                });
            } else {
                requires.push(condition.rule.clone());
            }
        }
    }

    /// Bind the edge a socket was filled with.
    ///
    /// The socket types what may arrive and the composition names what
    /// did, so both are checked here: the socket's declared resource
    /// against the edge's, and the declaring intent's own constraints
    /// against it as if it were an ordinary argument.
    fn bind_socket(
        &mut self,
        intent_index: usize,
        reference: u32,
        param: ParamType,
        at: (u32, u32),
    ) -> Result<(Value, NodeInput), AdmissionError> {
        let intent = &self.intents[intent_index];
        let (node_index, param_index) = at;
        let reference = &reference;

        let Some((decl, binding)) = usize::try_from(*reference).ok().and_then(|position| {
            Some((
                intent.sockets.get(position)?,
                intent.bindings.get(position)?,
            ))
        }) else {
            return Err(AdmissionError::UnknownSocket {
                node: node_index,
                socket: *reference,
            });
        };
        if !param.is_edge() {
            return Err(AdmissionError::SocketForValueParam {
                node: node_index,
                param: param_index,
            });
        }
        let intent_at = u32::try_from(intent_index).expect("intents are bounded by MAX_SUBINTENTS");
        let (
            Socket::Value {
                resource: declared,
                constraints,
            },
            Binding::Value {
                intent: source_intent,
                edge,
            },
        ) = (decl, *binding)
        else {
            // A socket shaped for authority fills no argument: an
            // argument takes value, and a proof is not value.
            return Err(AdmissionError::SocketForValueParam {
                node: node_index,
                param: param_index,
            });
        };
        let source_intent =
            usize::try_from(source_intent).map_err(|_| AdmissionError::TooManyNodes)?;
        let producer = usize::try_from(edge.producer).map_err(|_| AdmissionError::TooManyNodes)?;
        let source = self.flat_of[source_intent][producer];
        let declared = *declared;
        let (value, input) = bind_edge(
            &self.outputs,
            &mut self.consumed,
            (source, edge.output),
            constraints,
            param,
            (node_index, param_index),
            |resource| {
                if resource == declared {
                    Ok(())
                } else {
                    Err(AdmissionError::SocketResourceMismatch {
                        intent: intent_at,
                        socket: *reference,
                    })
                }
            },
        )?;
        Ok((value, input))
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
            .required()
            .filter(|rule| rule.judged() != Judged::AtMaterialization)
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
                EvidenceRef::Socket(reference) => {
                    // A socket the declaration typed and the composition
                    // filled. What is presented is the claim the
                    // *declaration* named — never whatever else the
                    // minting node happened to mint — so a composition
                    // cannot hand an intent authority its signer never
                    // asked for.
                    let Some((
                        Socket::Authority(wanted),
                        Binding::Authority {
                            intent: filled_from,
                            producer,
                        },
                    )) = usize::try_from(*reference).ok().and_then(|position| {
                        Some((
                            intent.sockets.get(position)?,
                            *intent.bindings.get(position)?,
                        ))
                    })
                    else {
                        return Err(AdmissionError::UnknownSocket {
                            node: node_index,
                            socket: *reference,
                        });
                    };
                    let source = usize::try_from(filled_from)
                        .ok()
                        .and_then(|source| self.flat_of.get(source))
                        .and_then(|flat| usize::try_from(producer).ok().and_then(|at| flat.get(at)))
                        .and_then(|flat| usize::try_from(*flat).ok())
                        .ok_or(AdmissionError::UnknownSocket {
                            node: node_index,
                            socket: *reference,
                        })?;
                    // The interleave orders a node after every socket it
                    // reaches, so the minting node has been judged and
                    // its claims are in hand.
                    let minted = self
                        .minted
                        .get(source)
                        .ok_or(AdmissionError::ForwardProof {
                            node: node_index,
                            producer,
                        })?;
                    if !minted.contains(wanted) {
                        return Err(AdmissionError::SocketClaimMismatch {
                            node: node_index,
                            socket: *reference,
                        });
                    }
                    evidence.push(*wanted);
                }
            }
        }
        judge_presented(&required, &evidence, node_index)?;
        Ok(evidence)
    }
}

/// Judge every rule this stage can decide, against what the node
/// presented.
///
/// What a node presented is signed content and a claim leaf reads
/// nothing else, so a rule made of them alone is decided here — before
/// anything routes, and before any leg could have committed on the
/// strength of it. The walk judges it again over the same set, where it
/// cannot fail: that redundancy is what lets a frame whose caller
/// commits without waiting carry one at all.
fn judge_presented(
    required: &[&Rule<JudgedLeaf>],
    evidence: &[Presented],
    node_index: u32,
) -> Result<(), AdmissionError> {
    for rule in required
        .iter()
        .filter(|rule| rule.judged() == Judged::AtAdmission)
    {
        let judged = rule.map_leaves(&mut |leaf| match leaf {
            JudgedLeaf::Claim(claim) => Ok(SealedLeaf::Claim(*claim)),
            // A rule this stage judges reads claims alone, which is what
            // put it here.
            JudgedLeaf::Presence { .. } | JudgedLeaf::Stored { .. } => {
                Err(AdmissionError::EvidenceUnsatisfied { node: node_index })
            }
        })?;
        if !judged.satisfied_by(evidence) {
            return Err(AdmissionError::EvidenceUnsatisfied { node: node_index });
        }
    }
    Ok(())
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

/// Refuse a frame whose declared prefix does not answer to the
/// authority it claimed.
///
/// One rule with two halves, and they are the same sentence read in
/// both directions: **an access reaching under no authority names its
/// own prefix, and an access reaching under one names another's.**
///
/// The first half is what bounds a declaration. Without it a package
/// reaches any cell it can name — a stranger's balance among them —
/// with no method's accessibility in the path, because reaching for a
/// cell is not calling the object that owns it.
///
/// The second is what keeps the reach from being a way out of the
/// injections. A reaching access earns no movement requirement of any
/// kind, which is right where the party reached is the one every
/// requirement would fire against and wrong where that party is the
/// frame itself: a component naming its own prefix under an authority
/// would be exempt from its own resources' entries while doing nothing
/// a plain access could not do.
///
/// Both halves are judged on the evaluated effect rather than on the
/// expression that produced it, and the second is the reason that
/// matters. The publish gate refuses an owner spelled `SelfAddr`, so an
/// author hears about it first — but every reach names its owner by
/// argument, so publish sees an expression rather than an address and
/// only the evaluated effect can answer.
///
/// The nullifier a bound subintent spends is not judged here: it sits
/// under its signer's prefix, no signature declared it, and it reaches
/// the routing view as a kernel effect rather than through any frame.
fn judge_prefixes(
    declaration: &Declaration,
    instance: Address,
    node_index: u32,
) -> Result<(), AdmissionError> {
    for (position, access) in declaration.ordered.iter().enumerate() {
        let clause = u32::try_from(position).unwrap_or(u32::MAX);
        let owner = access.effect.target.owner();
        match (access.reach.is_some(), owner == instance) {
            (false, false) => {
                return Err(AdmissionError::ForeignDeclaration {
                    node: node_index,
                    clause,
                    owner,
                });
            }
            (true, true) => {
                return Err(AdmissionError::ReachesItself {
                    node: node_index,
                    clause,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// The requirement one entry puts on a frame speaking as `speaking_for`,
/// or nothing where it demands nothing of it.
///
/// The one door every actor question goes through. What separates
/// issuance, destruction and reach is where the entry is found — a
/// declaration derives one, a presented record carries the other two —
/// and from there they are one question asked three times: does the
/// entry decode, does the frame's own claim already satisfy it, and what
/// is left for the caller to answer.
///
/// Asking it in one place is what keeps the answer one answer. A
/// composer predicts this to know what to present, so a site that
/// subtracted where another did not would emit a graph admission
/// refuses — and there is no way to notice that from either site alone.
///
/// # Errors
///
/// [`AdmissionError::Unadmitted`] where no entry admits the behaviour,
/// and [`AdmissionError::EntryMalformed`] where the entry's bytes are
/// not a rule an actor question may carry.
fn injected_entry(
    entry: Option<&RuleBytes>,
    resource: ResourceAddr,
    behaviour: GrantedBehaviour,
    speaking_for: Option<Presented>,
    node_index: u32,
) -> Result<Option<Injected>, AdmissionError> {
    let malformed = || AdmissionError::EntryMalformed {
        node: node_index,
        resource,
        behaviour,
    };
    let sealed = entry.ok_or(AdmissionError::Unadmitted {
        node: node_index,
        resource,
        behaviour,
    })?;
    let Some(rule) = behaviour
        .demanded(sealed, speaking_for)
        .map_err(|_| malformed())?
    else {
        return Ok(None);
    };
    Ok(Some(Injected {
        rule: judged_claims(&rule).ok_or_else(malformed)?,
        asks: Asks::Entry(rule),
        resource,
        behaviour,
    }))
}

/// Resolve the resource this frame issues, and inject the authority
/// entries its direction is held to.
///
/// The entry comes from the declaration rather than from a presented
/// record, and the asymmetry with a movement entry is the honest one: a
/// movement rule governs a resource a *caller* named, so the presented
/// record is what makes it trustworthy; an issuance rule governs one the
/// *declaration* derives, and re-derivation is the address itself.
///
/// **A frame speaks for itself.** An entry the executing instance's own
/// claim already satisfies is not appended at all — which reproduces the
/// derivation gate exactly, leaves a rule naming a badge meaning
/// delegated issuance, and costs the ordinary issuer nothing. The
/// extension is this entry's alone and never the node's evidence: a
/// claim on the target minted into that set would satisfy every
/// `Claim(SelfAddr)` gate standing beside it, which is the shape an
/// account's own spending gates take.
/// A requirement the protocol put on a frame, and the entry that put it
/// there.
///
/// Nothing here is declared. A package writes no word about any of it —
/// which is what makes omission inexpressible — so a reader meeting one
/// of these is meeting the protocol speak, and the resource and the
/// behaviour are what it speaks for. That provenance is why these are
/// carried out of the injection rather than pushed into the frame and
/// forgotten: the rule alone says what must hold and cannot say who
/// asked, and a key is a hash that inverts to nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Injected {
    /// What must hold, resolved: every holding a key under the party the
    /// question is about.
    pub rule: Rule<JudgedLeaf>,
    /// What was asked, before resolving hashed the subject away.
    pub asks: Asks,
    /// The resource whose entry demands it.
    pub resource: ResourceAddr,
    /// Which of that resource's entries.
    pub behaviour: GrantedBehaviour,
}

/// What an injected requirement asks, in the terms it was asked in.
///
/// Beside the resolved rule rather than derived from it, because
/// resolving is one-way: a holding becomes the presence of a key, and a
/// key is a hash of the party and the badge that inverts to neither. So
/// a reader handed the rule alone can see that some leaf must be there
/// and never which, which is the whole reason a refusal is unreadable
/// without this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asks {
    /// The entry's own sealed rule.
    Entry(StoredRule),
    /// That the party whose cell moves is not halted — which every
    /// movement of a resource granting `Freeze` reads, and which no
    /// entry states because it is a fact about the holder rather than a
    /// rule about anyone.
    Unhalted,
}

/// An actor question's rule read as judged leaves.
///
/// Such a rule reads claims and the seal refuses it otherwise, so a
/// holding here is a record that could not have been sealed — `None`,
/// for the caller to name in its own terms.
fn judged_claims(rule: &StoredRule) -> Option<Rule<JudgedLeaf>> {
    rule.map_leaves(&mut |leaf| match leaf {
        SealedLeaf::Claim(claim) => Ok(JudgedLeaf::Claim(*claim)),
        SealedLeaf::Held { .. } => Err(()),
    })
    .ok()
}

fn inject_issuance_rules(
    hasher: &dyn Hasher,
    signature: &MethodSignature,
    target: Address,
    config: &[Value],
    frame: &Declaration,
    node_index: u32,
) -> Result<(Vec<IssuanceGrant>, Vec<Injected>), AdmissionError> {
    let mut granted = Vec::with_capacity(signature.issues.len());
    let mut injected = Vec::new();
    for issuance in &signature.issues {
        // The rules the mark grants ride the grant's own address, so what
        // a body issues is what a gate naming the same resource resolves
        // to.
        let rules = issuance
            .grants
            .resolve(hasher, target, config)
            .map_err(|source| AdmissionError::Eval {
                node: node_index,
                source: source.into(),
            })?;
        let resource =
            granting_issued_resource(hasher, target, issuance.kind, &rules, &issuance.mark);
        granted.push(IssuanceGrant {
            resource,
            kind: issuance.kind,
            direction: issuance.direction,
        });
        // A frame that creates the resource's record is the frame
        // founding its supply, and founding is not minting: the record's
        // own absent-door is the cap, so a resource granting no `Mint`
        // entry comes up holding what its creation says and can never
        // hold more. Read off the declaration rather than declared, on
        // the terms the instantiation fence is — a node that writes the
        // leaf is the creation itself.
        let record = EffectTarget::Point(resource_record_key(hasher, target, resource));
        let founding = frame.ordered.iter().any(|access| {
            access.effect.target == record && matches!(access.effect.mode, Mode::Write { .. })
        });
        if founding {
            continue;
        }
        // A resource is not an acting identity, so a target that issues
        // one is callable and names a claim.
        let own = Presented::of_address(target).ok_or(AdmissionError::Unadmitted {
            node: node_index,
            resource,
            behaviour: GrantedBehaviour::Mint,
        })?;
        for behaviour in issuance.direction.behaviours() {
            let entry = injected_entry(
                rules.get(*behaviour),
                resource,
                *behaviour,
                Some(own),
                node_index,
            )?;
            injected.extend(entry);
        }
    }
    Ok((granted, injected))
}

/// Resolve the per-bucket grants this frame's declared destructions
/// earn, and inject the entries admitting them.
///
/// The mirror of an issuance and not a case of one. An issuance governs
/// a resource the *declaration* derives, so re-derivation is the address
/// itself; a destruction governs one a **caller** named, so the
/// presented record is what makes the rule trustworthy — the same reason
/// a movement entry needs one.
///
/// Absence withholds, twice over: a resource whose record was not
/// presented grants nothing here, and one granting no `Burn` entry is
/// one nobody may destroy. Neither needs a class byte to tell it from a
/// bypass, because withholding an authority is the safe direction —
/// what the class exists for is the movement a missing record would
/// otherwise let through.
fn inject_destruction_rules(
    grants: &PresentedGrants,
    signature: &MethodSignature,
    inputs: &[NodeInput],
    evidence_of: Address,
    node_index: u32,
) -> Result<(Vec<IssuanceGrant>, Vec<Injected>), AdmissionError> {
    let mut granted = Vec::with_capacity(signature.destroys.len());
    let mut injected = Vec::new();
    for param in &signature.destroys {
        let Some(NodeInput::Edge {
            resource, content, ..
        }) = usize::try_from(*param).ok().and_then(|at| inputs.get(at))
        else {
            return Err(AdmissionError::DestroysNoEdge {
                node: node_index,
                param: *param,
            });
        };
        // The frame speaks for itself here too, though it rarely is the
        // party: an account destroying a token it holds is not the
        // token's issuer, so a rule naming the issuer reaches the call
        // and the caller answers for it.
        let entry = injected_entry(
            grants
                .rules(*resource)
                .and_then(|rules| rules.get(GrantedBehaviour::Burn)),
            *resource,
            GrantedBehaviour::Burn,
            Presented::of_address(evidence_of),
            node_index,
        )?;
        granted.push(IssuanceGrant {
            resource: *resource,
            kind: content.kind(),
            direction: Issued::Burned,
        });
        injected.extend(entry);
    }
    Ok((granted, injected))
}

/// Inject the entry admitting each access that reaches a foreign prefix.
///
/// The reach is issuer-initiated by construction — a declaration cannot
/// name a stranger's cell without saying which authority lets it — so
/// what governs it is the reached resource's own sealed rule and nothing
/// else. The resource is the one the key is derived from, which is what
/// makes the entry judged always the entry of the thing actually
/// reached.
///
/// Absence withholds, and here that is the whole of the old refusal: a
/// resource granting no entry for the behaviour is one nobody may reach
/// a holder of, which is every resource until its issuer says otherwise.
fn inject_reach_rules(
    grants: &PresentedGrants,
    frame: &Declaration,
    reaching: Address,
    node_index: u32,
) -> Result<Vec<Injected>, AdmissionError> {
    let mut injected = Vec::new();
    let mut wanted: Vec<Reach> = Vec::new();
    for access in &frame.ordered {
        let Some(reach) = access.reach else {
            continue;
        };
        if !wanted.contains(&reach) {
            wanted.push(reach);
        }
    }
    for Reach {
        behaviour,
        resource,
    } in wanted
    {
        // The frame speaks for itself here as it does at every other
        // injected authority entry: an issuer whose own entry names it
        // is the authority, and asking it to prove it is asking for a
        // claim on a component, which only that component can mint.
        let entry = injected_entry(
            grants
                .rules(resource)
                .and_then(|rules| rules.get(behaviour)),
            resource,
            behaviour,
            Presented::of_address(reaching),
            node_index,
        )?;
        injected.extend(entry);
    }
    Ok(injected)
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
/// owner is the frame's own instance, which [`judge_prefixes`] has already
/// held every access to, so nothing here adds a participant.
fn inject_movement_rules(
    hasher: &dyn Hasher,
    grants: &PresentedGrants,
    frame: &mut Declaration,
    total: bool,
    node_index: u32,
) -> Result<Vec<Injected>, AdmissionError> {
    let mut injected = Vec::new();
    // Which requirements this frame earns, before any is built: an access
    // whose mode reaches both directions earns both, and only a
    // reservation carries its own.
    let mut wanted: Vec<(Address, ResourceAddr, GrantedBehaviour)> = Vec::new();
    for access in &frame.ordered {
        // A reaching access earns none of them, and the exemption is the
        // whole class rather than one entry: the party reached is by
        // construction the party every injected requirement would fire
        // against. A halt fence would make a frozen holder unrecallable,
        // a withdraw requirement would leave a restricted resource
        // recallable only from parties who did not need recalling, and a
        // soulbound credential would be unrevocable — which would take
        // revocation, the primary brake, with it.
        if access.reach.is_some() {
            continue;
        }
        let Some(resource) = access.holds else {
            continue;
        };
        let owner = access.effect.target.owner();
        let Some(moves) = access.effect.mode.moves() else {
            continue;
        };
        for behaviour in GrantedBehaviour::earned_by(moves) {
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
        // A resource whose issuer can halt a holder is one whose every
        // movement reads that holder's flag. Injected here rather than
        // declared, on the same terms the movement entries are: a
        // package will not declare a fence it does not want, and a
        // component holding value declares no halt leaf and cannot be
        // made to. Granting `Freeze` is what puts the resource in the
        // class whose record cannot be withheld, so the read fails
        // closed.
        if rules.get(GrantedBehaviour::Freeze).is_some() {
            let halted = EffectTarget::Point(child_key(
                hasher,
                owner,
                HALT,
                &[Value::Address(resource.address()).canonical_bytes()],
            ));
            declare_read(frame, halted);
            // Once per party and resource however many directions the
            // access moves in: one flag answers every movement of it.
            let fence = Injected {
                rule: Rule::Require(JudgedLeaf::Presence {
                    target: halted,
                    expect: Presence::Absent,
                }),
                asks: Asks::Unhalted,
                resource,
                behaviour: GrantedBehaviour::Freeze,
            };
            if !injected.contains(&fence) {
                injected.push(fence);
            }
        }
        let Some(sealed) = rules.get(behaviour) else {
            continue;
        };
        // No subtraction reaches a movement entry: it resolves against
        // the party whose cell moves, and the executing frame's identity
        // says nothing about them. Asked through the same door anyway,
        // so which entries a frame speaks for itself on is one answer.
        let Some(rule) =
            behaviour
                .demanded(sealed, None)
                .map_err(|_| AdmissionError::EntryMalformed {
                    node: node_index,
                    resource,
                    behaviour,
                })?
        else {
            continue;
        };
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
        let resolved = rule.map_leaves(&mut |leaf| -> Result<_, AdmissionError> {
            match leaf {
                SealedLeaf::Held { badge, holding } => {
                    let target = holding_target(hasher, owner, *badge, *holding);
                    declare_read(frame, target);
                    Ok(JudgedLeaf::Presence {
                        target,
                        expect: Presence::Present,
                    })
                }
                // A movement entry may also ask whether this transaction was
                // approved, which is a question about the call rather than
                // about the mover — so the claim rides the node's evidence
                // like any other.
                SealedLeaf::Claim(claim) => Ok(JudgedLeaf::Claim(*claim)),
            }
        })?;
        // A rule mixing the two asks about the mover and about the call
        // at once, and no stage before the leg holds both — so it is a
        // verdict the declaring node's own walk reaches, which a frame
        // whose caller commits without waiting may not carry.
        if total && !resolved.judged().before_any_leg() {
            return Err(AdmissionError::MovementUnanswerable {
                node: node_index,
                resource,
                behaviour,
            });
        }
        injected.push(Injected {
            rule: resolved,
            asks: Asks::Entry(rule),
            resource,
            behaviour,
        });
    }
    Ok(injected)
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
            reach: None,
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
    /// The resource this node issues, already derived where its entries
    /// were injected — so the address a rule was resolved against and
    /// the address the grant carries are one derivation.
    issues: Vec<IssuanceGrant>,
    inputs: &'a EvalInputs<'a>,
    hasher: &'a dyn Hasher,
}

/// The argument one handle binding lowers to: the capability each of
/// the site's elements names, and an absence where its guard did not
/// fire.
///
/// One function for both shapes, because a site is one shape: a plain
/// clause is a site of one element, a `for-each` clause's body site is
/// as wide as the list its loop mapped over, and a clause guarded out
/// contributes an absence rather than shortening anything. The
/// declaration recorded both — the spans for the first, the expansions
/// for the second — so nothing here computes a position.
fn bind_site(
    signature: &MethodSignature,
    declaration: &Declaration,
    clause: u32,
    site: u32,
    offset: u32,
) -> Result<CallArg, String> {
    let index = usize::try_from(clause).map_err(|_| format!("clause {clause} is out of range"))?;
    let declared = signature
        .effects
        .get(index)
        .ok_or_else(|| format!("clause {clause} is not declared"))?;

    let entries: Vec<Option<u32>> = if let Clause::ForEach { body, .. } = declared {
        let backed = usize::try_from(site)
            .ok()
            .and_then(|at| body.get(at))
            .is_some_and(supports);
        if !backed {
            return Err(format!(
                "site {site} of clause {clause} materializes nothing"
            ));
        }
        declaration
            .elements(clause, site)
            .ok_or_else(|| format!("clause {clause} has no site {site} to run"))?
            .to_vec()
    } else {
        // A plain clause is one site of one element: the span the
        // evaluation recorded is one entry when the clause was declared
        // and none when its guard ruled it out.
        if !supports(declared) {
            return Err(format!("clause {clause} materializes nothing"));
        }
        let (start, len) = declaration
            .clause_spans
            .get(index)
            .copied()
            .ok_or_else(|| format!("clause {clause} has no span"))?;
        match len {
            1 => vec![Some(start)],
            0 => vec![None],
            _ => {
                return Err(format!(
                    "clause {clause} evaluated to {len} accesses, which no handle names"
                ));
            }
        }
    };

    let entries = entries
        .into_iter()
        .map(|entry| {
            entry.map_or(Ok(None), |position| {
                position
                    .checked_add(offset)
                    .map(Some)
                    .ok_or_else(|| "the capability table overflowed".to_owned())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CallArg::Site { entries })
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
        issues,
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
            AbiParam::Handle { clause, site } => {
                bind_site(signature, declaration, *clause, *site, offset).map_err(&unbindable)?
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
        issues,
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
