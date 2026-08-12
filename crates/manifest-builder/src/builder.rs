//! The builder: append-only node construction with affine edge handles.
//!
//! Each rule the builder keeps maps to an admission error it makes
//! unwritable or catches early. Nodes only append, so an edge handle can
//! only name an earlier node and `ForwardEdge` has no spelling. A
//! [`Bucket`] is not `Copy` and every consumption takes it by value, so
//! `DoubleConsumption` is a move error at compile time. The one linearity
//! rule an affine type cannot carry — every minted output *must* be
//! consumed — is [`GraphBuilder::build`]'s check, surfaced as
//! [`BuildError::DanglingOutput`] before a signature is ever made.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use hyperscale_vm_effects::{
    CallTarget, Constraint, EdgeRef, EvidenceRef, GraphArg, GraphNode, MAX_MANIFEST_NODES,
    ManifestGraph, PrincipalAddr, ResourceRef,
};

use crate::args::Args;

/// Why [`GraphBuilder::build`] refused to emit a graph.
///
/// Everything here is a graph admission would also refuse; the builder
/// merely says so before the graph is signed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// An output no argument consumed and no yield exported — admission
    /// would reject it as an unconsumed edge.
    #[error("output {output} of node {producer} is never consumed")]
    DanglingOutput {
        /// The producing node.
        producer: u32,
        /// The output slot.
        output: u32,
    },
    /// More nodes than admission accepts.
    #[error("graph has more nodes than admission can address")]
    TooManyNodes,
}

/// One output edge of a node already added to a [`GraphBuilder`], with the
/// constraints its eventual consumer will assert.
///
/// Deliberately neither `Copy` nor `Clone`: an edge has exactly one
/// consumer, and a handle that can only be moved makes consuming it twice
/// a compile error rather than an admission verdict. Constraints attach
/// here — at the handle the consumer holds — because that is where the
/// signed form carries them: on the consuming argument, not the producer.
#[derive(Debug)]
pub struct Bucket {
    /// The minting builder's identity; binding checks it, because an
    /// edge reference is meaningless in any other builder's index space.
    pub(crate) builder: u64,
    /// The edge this handle stands for.
    pub(crate) edge: EdgeRef,
    /// The edge's static resource type where the producing call's
    /// signature determined it, and `None` where nothing did.
    ///
    /// Derived rather than asserted: it is what the producer's declared
    /// output type evaluates to, so binding it asserts a
    /// [`Constraint::ResourceIs`] the author never had to write. The
    /// untyped path leaves it `None`, because a builder reading no
    /// metadata has nothing to derive it from.
    pub(crate) resource: Option<ResourceRef>,
    /// The consumer's constraints, in the order they were asserted.
    pub(crate) constraints: Vec<Constraint>,
}

impl Bucket {
    /// The edge's static resource type, where the producing signature
    /// determined it.
    #[must_use]
    pub const fn resource(&self) -> Option<ResourceRef> {
        self.resource
    }

    /// Assert an already-built [`Constraint`] — the generic form of the
    /// typed assertions below, for callers holding the constraint as a
    /// value.
    #[must_use]
    pub fn constrain(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Assert the edge carries at least `amount` at execution.
    #[must_use]
    pub fn min(self, amount: u128) -> Self {
        self.constrain(Constraint::MinAmount(amount))
    }

    /// Assert the edge carries at most `amount` at execution.
    #[must_use]
    pub fn max(self, amount: u128) -> Self {
        self.constrain(Constraint::MaxAmount(amount))
    }

    /// Assert the edge's static resource type; checked at admission.
    ///
    /// Two classes name a resource — an ordinary one and the protocol's
    /// own — so the argument is the pair of them rather than a single
    /// class, and naming an account or a package here does not compile.
    ///
    /// # Panics
    ///
    /// On an edge whose producing signature already typed it as something
    /// else. Admission would refuse the assertion anyway; a handle that
    /// knows its own type can say so at the line that wrote it.
    #[must_use]
    pub fn resource_is(self, resource: impl Into<ResourceRef>) -> Self {
        let resource = resource.into();
        assert!(
            self.resource.is_none_or(|derived| derived == resource),
            "the producing signature types this edge as a different resource"
        );
        self.constrain(Constraint::ResourceIs(resource))
    }

    /// The bound argument this handle stands for: the edge, the resource
    /// type its producer determined, and the constraints its consumer
    /// asserted.
    ///
    /// A derived type binds as a leading [`Constraint::ResourceIs`] unless
    /// the consumer asserted one itself, which is the whole of "the
    /// manifest's own guarantee is on by default": the assertion rides
    /// every typed edge without the author writing it, and an author who
    /// writes one anyway keeps the one they wrote, for admission to judge.
    pub(crate) fn into_arg(self) -> GraphArg {
        let asserted = self
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::ResourceIs(_)));
        let derived = self.resource.filter(|_| !asserted);
        let mut constraints = Vec::with_capacity(self.constraints.len() + usize::from(!asserted));
        constraints.extend(derived.map(Constraint::ResourceIs));
        constraints.extend(self.constraints);
        GraphArg::Edge {
            edge: self.edge,
            constraints,
        }
    }
}

/// The enclosing intent's declared yield parameter, by position — the
/// typed hole an envelope binds to another intent's exported edge.
///
/// Not tied to a builder: the parameter's declaration lives on the
/// [`IntentDecl`], and whether the position exists and is consumed exactly
/// once is admission's judgement over the whole envelope. Like a
/// [`Bucket`] it is affine — one token binds one argument.
///
/// [`IntentDecl`]: hyperscale_vm_effects::IntentDecl
#[derive(Debug)]
pub struct Param(
    /// The parameter position within the enclosing intent's declaration.
    pub u32,
);

/// Distinguishes concurrently live builders, so a [`Bucket`] minted by one
/// cannot be quietly spent in another's index space.
static NEXT_BUILDER: AtomicU64 = AtomicU64::new(0);

/// An append-only [`ManifestGraph`] under construction.
///
/// The builder is convenience, never judgement: admission re-checks
/// everything it enforces, deterministically and on every node, so a bug
/// here can cost a signer a rejected transaction but can never admit a
/// graph the protocol would not. Its whole contract is that a graph it
/// emits without error passes the structural half of admission — order,
/// linearity, addressability. Arity and typing against package metadata
/// remain admission's, because the builder does not read metadata: the
/// output count a [`call`] mints is the caller's claim, checked where every
/// claim is.
///
/// [`call`]: GraphBuilder::call
#[derive(Debug)]
pub struct GraphBuilder {
    id: u64,
    nodes: Vec<GraphNode>,
    /// One entry per minted output, per node, in node order.
    outputs: Vec<Vec<Output>>,
    /// Where unconsumed outputs go at [`build`](Self::build), if the
    /// author named somewhere.
    rest: Option<PrincipalAddr>,
}

/// One minted output slot: what it carries, and whether anything took it.
#[derive(Debug)]
struct Output {
    resource: Option<ResourceRef>,
    consumed: bool,
}

impl GraphBuilder {
    /// A builder with no nodes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: NEXT_BUILDER.fetch_add(1, Ordering::Relaxed),
            nodes: Vec::new(),
            outputs: Vec::new(),
            rest: None,
        }
    }

    /// Route whatever the author did not: at [`build`](Self::build), every
    /// still-unconsumed output is deposited to `sink` instead of refusing
    /// the graph.
    ///
    /// Explicit consumption always wins — the policy only sees outputs
    /// nothing took — and there is no default policy, because silently
    /// routing value somewhere is worse than refusing to build. Naming the
    /// sink is the author saying where their own change goes.
    ///
    /// The sink is a principal because that is what makes the appended
    /// node well-formed without reading anything: every principal answers
    /// through the protocol's account blueprint, and a deposit there takes
    /// one bucket and produces nothing.
    pub const fn rest_to(&mut self, sink: PrincipalAddr) {
        self.rest = Some(sink);
    }

    /// Append an invocation of `method` on `target` and mint its `N`
    /// output edges, most often named by destructuring:
    /// `let [funds] = builder.call(...)`, or `let [] = ...` for a method
    /// producing nothing.
    ///
    /// `N` is the caller's claim about the method's output arity; the
    /// builder holds the claim to its own linearity rules, and admission
    /// judges it against the method's declared outputs.
    ///
    /// The target is a class that answers calls — an account or an
    /// instance. A package address is code and a resource address is a
    /// supply, so naming either as a target does not compile rather than
    /// failing admission.
    ///
    /// # Panics
    ///
    /// On a [`Bucket`] argument minted by a different builder, and on more
    /// nodes or outputs than a `u32` can address — the latter far past
    /// [`MAX_MANIFEST_NODES`], which [`build`](Self::build) enforces as an
    /// error rather than a panic.
    #[must_use = "every minted output must be consumed for the graph to build"]
    pub fn call<const N: usize>(
        &mut self,
        target: impl Into<CallTarget>,
        method: impl Into<String>,
        args: impl Args,
    ) -> [Bucket; N] {
        self.call_presenting(target, method, args, BTreeSet::new())
    }

    /// The same call, presenting the enclosing intent's signature badge —
    /// what a guarded method takes.
    ///
    /// The typed builder reads which methods need this off their
    /// signatures; here the author says so, because a bare graph builder
    /// has no metadata to consult.
    ///
    /// # Panics
    ///
    /// As [`call`](Self::call).
    #[must_use = "every minted output must be consumed for the graph to build"]
    pub fn call_signed<const N: usize>(
        &mut self,
        target: impl Into<CallTarget>,
        method: impl Into<String>,
        args: impl Args,
    ) -> [Bucket; N] {
        self.call_presenting(
            target,
            method,
            args,
            BTreeSet::from([EvidenceRef::IntentSignature]),
        )
    }

    #[must_use = "every minted output must be consumed for the graph to build"]
    fn call_presenting<const N: usize>(
        &mut self,
        target: impl Into<CallTarget>,
        method: impl Into<String>,
        args: impl Args,
        evidence: BTreeSet<EvidenceRef>,
    ) -> [Bucket; N] {
        let args = args.bind_all(self);
        let producer = self.push(target.into(), method.into(), args, vec![None; N], evidence);
        std::array::from_fn(|output| {
            self.mint(
                producer,
                u32::try_from(output).expect("more outputs than an edge can name"),
            )
        })
    }

    /// Append a node whose arguments are already bound, consuming every
    /// edge among them, and reserve its `outputs` slots.
    ///
    /// Binding and appending are separate so that a layer holding the
    /// target's signature can judge the bound arguments against it and
    /// refuse *before* anything is appended: a refusal that had already
    /// marked its edges consumed would leave the builder describing a
    /// graph it never built.
    pub(crate) fn push(
        &mut self,
        target: CallTarget,
        method: String,
        args: Vec<GraphArg>,
        outputs: Vec<Option<ResourceRef>>,
        evidence: BTreeSet<EvidenceRef>,
    ) -> u32 {
        let producer = u32::try_from(self.nodes.len()).expect("more nodes than an edge can name");
        for arg in &args {
            if let GraphArg::Edge { edge, .. } = arg {
                self.consume(*edge);
            }
        }
        self.nodes.push(GraphNode {
            target,
            method,
            args,
            evidence,
        });
        self.outputs.push(
            outputs
                .into_iter()
                .map(|resource| Output {
                    resource,
                    consumed: false,
                })
                .collect(),
        );
        producer
    }

    /// A handle on one of a pushed node's minted outputs, carrying the
    /// resource its producing signature typed the slot with.
    ///
    /// # Panics
    ///
    /// On a slot this builder never minted.
    pub(crate) fn mint(&self, producer: u32, output: u32) -> Bucket {
        let slot = &self.outputs[usize::try_from(producer).expect("minted indices fit")]
            [usize::try_from(output).expect("minted indices fit")];
        Bucket {
            builder: self.id,
            edge: EdgeRef { producer, output },
            resource: slot.resource,
            constraints: Vec::new(),
        }
    }

    /// How many nodes have been appended — the index the next call takes,
    /// which is what admission will number it by.
    pub(crate) fn len(&self) -> u32 {
        u32::try_from(self.nodes.len()).expect("more nodes than an edge can name")
    }

    /// Refuse a handle this builder did not mint, whose indices its tables
    /// cannot mean anything by.
    ///
    /// # Panics
    ///
    /// On a bucket minted by a different builder.
    pub(crate) fn check(&self, bucket: &Bucket) {
        assert_eq!(
            bucket.builder, self.id,
            "a bucket must be consumed by the builder that minted it"
        );
    }

    /// Consume an output as a yield edge: bound by the enclosing
    /// envelope's [`YieldBinding`] to another intent's declared parameter,
    /// rather than by a node of this graph.
    ///
    /// # Panics
    ///
    /// On a bucket carrying constraints — a yield's constraints are the
    /// consuming parameter's declaration, and accepting them here would
    /// drop them silently — and on a bucket minted by a different builder.
    ///
    /// [`YieldBinding`]: hyperscale_vm_effects::YieldBinding
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the bucket by value is the consumption; a borrow would let it be spent twice"
    )]
    pub fn export(&mut self, bucket: Bucket) -> EdgeRef {
        assert!(
            bucket.constraints.is_empty(),
            "a yield edge's constraints belong on the consuming intent's parameter"
        );
        self.check(&bucket);
        self.consume(bucket.edge);
        bucket.edge
    }

    /// Mark one minted output consumed. Called once per bucket by
    /// construction: every caller takes the bucket by value.
    fn consume(&mut self, edge: EdgeRef) {
        let producer = usize::try_from(edge.producer).expect("minted indices fit");
        let output = usize::try_from(edge.output).expect("minted indices fit");
        self.outputs[producer][output].consumed = true;
    }

    /// Emit the graph, checking the one linearity rule the handles cannot
    /// carry: every minted output was consumed — by an argument or by
    /// [`export`](Self::export).
    ///
    /// A builder carrying a [`rest_to`](Self::rest_to) policy deposits
    /// what dangles to the named sink instead, so only a policy-free
    /// builder refuses.
    ///
    /// # Errors
    ///
    /// [`BuildError::DanglingOutput`] for the first unconsumed output in
    /// node order; [`BuildError::TooManyNodes`] past
    /// [`MAX_MANIFEST_NODES`], counted after any rest edges are routed.
    pub fn build(mut self) -> Result<ManifestGraph, BuildError> {
        if let Some(sink) = self.rest {
            // Read whole first: routing a rest edge appends to the very
            // table the walk reads.
            let rests: Vec<EdgeRef> = self.dangling().collect();
            for edge in rests {
                let arg = self.mint(edge.producer, edge.output).into_arg();
                self.push(
                    sink.into(),
                    "deposit".into(),
                    vec![arg],
                    Vec::new(),
                    BTreeSet::new(),
                );
            }
        }
        if self.nodes.len() > MAX_MANIFEST_NODES {
            return Err(BuildError::TooManyNodes);
        }
        if let Some(edge) = self.dangling().next() {
            return Err(BuildError::DanglingOutput {
                producer: edge.producer,
                output: edge.output,
            });
        }
        Ok(ManifestGraph { nodes: self.nodes })
    }

    /// Every minted output nothing has taken, in node order.
    fn dangling(&self) -> impl Iterator<Item = EdgeRef> + '_ {
        self.outputs
            .iter()
            .enumerate()
            .flat_map(|(producer, outputs)| {
                outputs
                    .iter()
                    .enumerate()
                    .filter(|(_, slot)| !slot.consumed)
                    .map(move |(output, _)| EdgeRef {
                        producer: u32::try_from(producer).expect("minted indices fit"),
                        output: u32::try_from(output).expect("minted indices fit"),
                    })
            })
    }
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_vm_effects::{
        Constraint, EdgeRef, EvidenceRef, GraphArg, GraphNode, ManifestGraph, PrincipalAddr,
        ResourceAddr, Value,
    };

    use super::{BuildError, GraphBuilder, Param};

    const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
    const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
    const RES: ResourceAddr = ResourceAddr::new([0xE1; 31]);

    #[test]
    fn a_transfer_builds_the_hand_written_graph() {
        let mut b = GraphBuilder::new();
        let [funds] = b.call_signed(ALICE, "withdraw", (RES, 100u128));
        let [] = b.call(BOB, "deposit", (funds.resource_is(RES).min(1),));
        assert_eq!(
            b.build(),
            Ok(ManifestGraph {
                nodes: vec![
                    GraphNode {
                        target: ALICE.into(),
                        method: "withdraw".into(),
                        args: vec![
                            GraphArg::Literal(Value::Address(RES.address())),
                            GraphArg::Literal(Value::U128(100)),
                        ],
                        evidence: [EvidenceRef::IntentSignature].into(),
                    },
                    GraphNode {
                        target: BOB.into(),
                        method: "deposit".into(),
                        args: vec![GraphArg::Edge {
                            edge: EdgeRef {
                                producer: 0,
                                output: 0,
                            },
                            constraints: vec![
                                Constraint::ResourceIs(RES.into()),
                                Constraint::MinAmount(1)
                            ],
                        }],
                        evidence: BTreeSet::new(),
                    },
                ],
            })
        );
    }

    #[test]
    fn a_dropped_output_is_a_dangling_edge() {
        let mut b = GraphBuilder::new();
        let [_funds] = b.call_signed(ALICE, "withdraw", (RES, 100u128));
        assert_eq!(
            b.build(),
            Err(BuildError::DanglingOutput {
                producer: 0,
                output: 0,
            })
        );
    }

    #[test]
    fn the_second_output_dangles_independently_of_the_first() {
        let mut b = GraphBuilder::new();
        let [taken, _rest] = b.call(ALICE, "take", (30u128,));
        let [] = b.call(BOB, "deposit", (taken,));
        assert_eq!(
            b.build(),
            Err(BuildError::DanglingOutput {
                producer: 0,
                output: 1,
            })
        );
    }

    #[test]
    fn an_export_consumes_without_a_node() {
        let mut b = GraphBuilder::new();
        let [funds] = b.call_signed(ALICE, "withdraw", (RES, 100u128));
        let yielded = b.export(funds);
        assert_eq!(
            yielded,
            EdgeRef {
                producer: 0,
                output: 0,
            }
        );
        let [] = b.call(ALICE, "deposit", (Param(0),));
        let graph = b.build().unwrap();
        assert_eq!(graph.nodes[1].args, vec![GraphArg::Param(0)]);
    }

    #[test]
    #[should_panic(expected = "consuming intent's parameter")]
    fn a_constrained_export_is_refused() {
        let mut b = GraphBuilder::new();
        let [funds] = b.call_signed(ALICE, "withdraw", (RES, 100u128));
        let _ = b.export(funds.min(1));
    }

    #[test]
    #[should_panic(expected = "the builder that minted it")]
    fn a_foreign_bucket_is_refused() {
        let mut minting = GraphBuilder::new();
        let [funds] = minting.call_signed(ALICE, "withdraw", (RES, 100u128));
        let mut other = GraphBuilder::new();
        #[allow(
            clippy::tuple_array_conversions,
            reason = "the tuple is an argument list, not a conversion"
        )]
        let [] = other.call(BOB, "deposit", (funds,));
    }
}
