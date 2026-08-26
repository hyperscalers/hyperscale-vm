//! Why admission refused, and where the refusal points.
//!
//! One enum over every verdict the walk can reach, and one total map
//! from a variant to the place a reader is sent — so a renderer over
//! refusals is total by construction rather than by review.

use hyperscale_vm_types::{Address, EffectConflict, ResourceAddr};

use super::MAX_SOCKETS;
use crate::dsl::EvalError;
use crate::instance::ResolveError;
use crate::resource::{GrantedBehaviour, ResourceKind};
use crate::types::MAX_VALUE_DEPTH;

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
    #[error("intent {intent} declares {expected} sockets, binds {found}")]
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
    /// A socket filled from the other channel: a value socket with a
    /// proof, or an authority socket with an edge.
    ///
    /// Judged where the bindings are checked, so the wrong half never
    /// reaches the destructures downstream — which would each refuse it,
    /// but as some other verdict whose sentence sends the composer to
    /// the wrong fix.
    #[error("intent {intent} socket {socket} is declared for {declared} and filled with {offered}")]
    SocketKindMismatch {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
        /// The channel the socket declares.
        declared: &'static str,
        /// What the composition filled it with.
        offered: &'static str,
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
    UnconsumedSocket {
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
    ///
    /// Both indices are the intent's own, on the terms
    /// [`Self::SocketClaimMismatch`] states.
    #[error("intent {intent}: node {node} references socket {socket}, which is not declared")]
    UnknownSocket {
        /// The intent the node and the socket both belong to.
        intent: u32,
        /// The consuming node, in that intent.
        node: u32,
        /// The socket it named, in that intent.
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
        "node {node} presents a record and calls `{method}`, which is not its component's seal \
         — drop the record from the envelope, or call the method that seals it"
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
    /// some other one is refused rather than quietly presenting it. A
    /// filling node that minted nothing at all is the same refusal —
    /// no claim it minted matches, because it minted none.
    ///
    /// A socket is declared per intent, so the intent is what says which
    /// socket `socket` names — and the node is stated in the same
    /// numbering, so both halves of the sentence are one intent's.
    #[error(
        "intent {intent}: node {node} presents socket {socket}, which is filled by no such claim"
    )]
    SocketClaimMismatch {
        /// The intent the node and the socket both belong to.
        intent: u32,
        /// The presenting node, in that intent.
        node: u32,
        /// The socket it presented, in that intent.
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
    ///
    /// Both indices are the intent's own, on the terms
    /// [`Self::ForwardEdge`] states.
    #[error(
        "intent {intent}: node {node} draws a proof from node {producer}, which is not earlier"
    )]
    ForwardProof {
        /// The intent both indices are numbered within.
        intent: u32,
        /// The consuming node, in that intent.
        node: u32,
        /// The producer the proof claims, in that intent.
        producer: u32,
    },
    /// A proof drawn from a node whose method mints no identity.
    ///
    /// Both indices are the intent's own, so this refusal and the one
    /// above read in one numbering — a composer comparing them is
    /// comparing the same two things.
    #[error(
        "intent {intent}: node {node} draws a proof from node {producer}, whose method does not mint"
    )]
    UnmintingProof {
        /// The intent both indices are numbered within.
        intent: u32,
        /// The consuming node, in that intent.
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
    ///
    /// Both indices are the intent's own, unlike everywhere else in this
    /// enum. The producer is the one the edge names and may be no node
    /// at all, which is the refusal — so there is nothing to flatten it
    /// against, and stating the consumer in the same numbering is what
    /// makes the two comparable.
    #[error(
        "intent {intent}: node {node} consumes an edge from node {producer}, which is not earlier"
    )]
    ForwardEdge {
        /// The intent both indices are numbered within.
        intent: u32,
        /// The consuming node, in that intent.
        node: u32,
        /// The producer the edge claims, in that intent.
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
        /// The clause that declared it, numbered in the preorder walk of
        /// the method's effects — the numbering the rendered listing
        /// gives its lines.
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
        /// The clause that declared it, numbered in the preorder walk of
        /// the method's effects — the numbering the rendered listing
        /// gives its lines.
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
    ///
    /// The reason is in the message as well as in the source. A composer
    /// reads whatever a `{}` gave them, and `EvalError`'s own messages —
    /// `argument 2 out of range`, `slot 5 keeps no value, so nothing
    /// reaches it` — are the whole of what says which expression, and
    /// were reaching nobody.
    #[error("evaluating node {node}: {source}")]
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
    /// A socket shaped for authority, passed where an argument goes.
    ///
    /// The parameter is not what is wrong: an argument takes value, and a
    /// proof is not value. What the composition wants is the socket
    /// presented as evidence rather than passed as an argument, and
    /// saying so is the difference between a refusal an author can act on
    /// and one that sends them to change the signature.
    #[error(
        "node {node} passes authority socket {socket} as argument {param}: an authority socket \
         is presented as evidence, never passed as a value"
    )]
    AuthoritySocketAsArgument {
        /// The offending node.
        node: u32,
        /// The parameter position it was passed at.
        param: u32,
        /// The socket, in the intent that declared it.
        socket: u32,
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

/// Where in a composition a refusal points.
///
/// A node index alone is not a place: it is flattened unless the refusal
/// is one of the few stated in an intent's own numbering, and a reader
/// holding the number cannot tell which. This says both, so one renderer
/// can place every refusal without knowing any of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Placed {
    /// The intent, where the refusal is stated in one intent's own
    /// numbering. `None` means the node below is the flattened one.
    pub intent: Option<u32>,
    /// The node the refusal is about.
    pub node: Option<u32>,
    /// The argument position, where the refusal is about one argument.
    /// Always a position in the call's own argument list — an ABI
    /// binding's position is [`abi`](Self::abi), a different list.
    pub param: Option<u32>,
    /// The effect clause, in a preorder walk of the method's effects.
    pub clause: Option<u32>,
    /// The ABI binding position, where the refusal is about one binding.
    /// A different list from the arguments: handles and guards come
    /// first, so an index into one names nothing in the other.
    pub abi: Option<u32>,
}

impl AdmissionError {
    /// Where this refusal points.
    ///
    /// Total over the enum, which is what makes a renderer over it total:
    /// a variant added without a place here does not compile, so no
    /// refusal can arrive somewhere a reader cannot be sent.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one total dispatch over every refusal variant
    pub const fn at(&self) -> Placed {
        match self {
            // Flattened, and about the node as a whole.
            Self::MovementForbidden { node, .. }
            | Self::RecordWithheld { node, .. }
            | Self::Unadmitted { node, .. }
            | Self::EntryMalformed { node, .. }
            | Self::PresentedForCall { node, .. }
            | Self::MissingEvidence { node, .. }
            | Self::MovementUnanswerable { node, .. }
            | Self::EvidenceUnsatisfied { node, .. }
            | Self::UnexpectedEvidence { node, .. }
            | Self::UnsignedEvidence { node, .. }
            | Self::SignatureForGuarded { node, .. }
            | Self::ArityMismatch { node, .. }
            | Self::OutputType { node, .. }
            | Self::Eval { node, .. } => Placed {
                intent: None,
                node: Some(*node),
                param: None,
                clause: None,
                abi: None,
            },
            // Flattened, and about one of its arguments.
            Self::DestroysNoEdge { node, param, .. }
            | Self::ParamKind { node, param, .. }
            | Self::EdgeForValueParam { node, param, .. }
            | Self::LiteralForBucketParam { node, param, .. }
            | Self::ResourceKindMismatch { node, param, .. }
            | Self::UnsatisfiableConstraint { node, param, .. }
            | Self::ResourceMismatch { node, param, .. }
            | Self::WrongDenomination { node, param, .. }
            | Self::DenominationType { node, param, .. }
            | Self::SocketForValueParam { node, param, .. }
            | Self::AuthoritySocketAsArgument { node, param, .. }
            | Self::ValueTooDeep { node, param, .. } => Placed {
                intent: None,
                node: Some(*node),
                param: Some(*param),
                clause: None,
                abi: None,
            },
            // Flattened, and about one ABI binding — a different list
            // from the arguments, so the position rides its own
            // coordinate and a renderer cannot quote an unrelated
            // argument for it.
            Self::UnbindableAbiParam { node, param, .. } => Placed {
                intent: None,
                node: Some(*node),
                param: None,
                clause: None,
                abi: Some(*param),
            },
            // Flattened, and about one of its declared clauses.
            Self::ForeignDeclaration { node, clause, .. }
            | Self::ReachesItself { node, clause, .. } => Placed {
                intent: None,
                node: Some(*node),
                param: None,
                clause: Some(*clause),
                abi: None,
            },
            // The producing node, flattened: what the edge resolved to
            // rather than what the composer wrote.
            Self::NoSuchOutput { producer, .. }
            | Self::DoubleConsumption { producer, .. }
            | Self::UnconsumedOutput { producer, .. } => Placed {
                intent: None,
                node: Some(*producer),
                param: None,
                clause: None,
                abi: None,
            },
            // Stated in the intent's own numbering, because the other
            // index in the sentence has no flattened form.
            Self::ForwardProof { intent, node, .. }
            | Self::UnmintingProof { intent, node, .. }
            | Self::ForwardEdge { intent, node, .. }
            | Self::UnknownSocket { intent, node, .. }
            | Self::SocketClaimMismatch { intent, node, .. } => Placed {
                intent: Some(*intent),
                node: Some(*node),
                param: None,
                clause: None,
                abi: None,
            },
            // About the intent rather than any one of its nodes.
            Self::BindingArity { intent, .. }
            | Self::TooManySockets { intent, .. }
            | Self::UnknownBinding { intent, .. }
            | Self::SocketKindMismatch { intent, .. }
            | Self::SocketResourceMismatch { intent, .. }
            | Self::UnconsumedSocket { intent, .. }
            | Self::SocketReused { intent, .. } => Placed {
                intent: Some(*intent),
                node: None,
                param: None,
                clause: None,
                abi: None,
            },
            // A budget, a shape, or a whole composition: nowhere to send
            // a reader that the sentence does not already say.
            Self::TooManyNodes { .. }
            | Self::TooManySubintents { .. }
            | Self::DuplicateSubintent { .. }
            | Self::CyclicSockets { .. }
            | Self::Resolve(..)
            | Self::TableOverflow { .. }
            | Self::Conflict(..)
            | Self::InstanceValueTooDeep { .. } => Placed {
                intent: None,
                node: None,
                param: None,
                clause: None,
                abi: None,
            },
        }
    }
}
