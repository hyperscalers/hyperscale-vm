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

use std::sync::atomic::{AtomicU64, Ordering};

use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, GraphNode, MAX_MANIFEST_NODES, ManifestGraph,
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
    /// The minting builder's identity; consumption checks it, because an
    /// edge reference is meaningless in any other builder's index space.
    pub(crate) builder: u64,
    /// The edge this handle stands for.
    pub(crate) edge: EdgeRef,
    /// The consumer's constraints, in the order they were asserted.
    pub(crate) constraints: Vec<Constraint>,
}

impl Bucket {
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
    #[must_use]
    pub fn resource_is(self, resource: Address) -> Self {
        self.constrain(Constraint::ResourceIs(resource))
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
    /// One consumption flag per minted output, per node, in node order.
    outputs: Vec<Vec<bool>>,
}

impl GraphBuilder {
    /// A builder with no nodes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: NEXT_BUILDER.fetch_add(1, Ordering::Relaxed),
            nodes: Vec::new(),
            outputs: Vec::new(),
        }
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
    /// # Panics
    ///
    /// On a [`Bucket`] argument minted by a different builder, and on more
    /// nodes or outputs than a `u32` can address — the latter far past
    /// [`MAX_MANIFEST_NODES`], which [`build`](Self::build) enforces as an
    /// error rather than a panic.
    #[must_use = "every minted output must be consumed for the graph to build"]
    pub fn call<const N: usize>(
        &mut self,
        target: Address,
        method: impl Into<String>,
        args: impl Args,
    ) -> [Bucket; N] {
        let producer = u32::try_from(self.nodes.len()).expect("more nodes than an edge can name");
        let args = args.bind_all(self);
        self.nodes.push(GraphNode {
            target,
            method: method.into(),
            args,
        });
        self.outputs.push(vec![false; N]);
        std::array::from_fn(|output| Bucket {
            builder: self.id,
            edge: EdgeRef {
                producer,
                output: u32::try_from(output).expect("more outputs than an edge can name"),
            },
            constraints: Vec::new(),
        })
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
        self.consume(&bucket);
        bucket.edge
    }

    /// Mark one minted output consumed. Called once per bucket by
    /// construction: every caller takes the bucket by value.
    ///
    /// # Panics
    ///
    /// On a bucket minted by a different builder, whose indices this one's
    /// tables cannot mean anything by.
    pub(crate) fn consume(&mut self, bucket: &Bucket) {
        assert_eq!(
            bucket.builder, self.id,
            "a bucket must be consumed by the builder that minted it"
        );
        let producer = usize::try_from(bucket.edge.producer).expect("minted indices fit");
        let output = usize::try_from(bucket.edge.output).expect("minted indices fit");
        self.outputs[producer][output] = true;
    }

    /// Emit the graph, checking the one linearity rule the handles cannot
    /// carry: every minted output was consumed — by an argument or by
    /// [`export`](Self::export).
    ///
    /// # Errors
    ///
    /// [`BuildError::DanglingOutput`] for the first unconsumed output in
    /// node order; [`BuildError::TooManyNodes`] past
    /// [`MAX_MANIFEST_NODES`].
    pub fn build(self) -> Result<ManifestGraph, BuildError> {
        if self.nodes.len() > MAX_MANIFEST_NODES {
            return Err(BuildError::TooManyNodes);
        }
        for (producer, outputs) in (0u32..).zip(&self.outputs) {
            let dangling = (0u32..)
                .zip(outputs)
                .find_map(|(output, consumed)| (!consumed).then_some(output));
            if let Some(output) = dangling {
                return Err(BuildError::DanglingOutput { producer, output });
            }
        }
        Ok(ManifestGraph { nodes: self.nodes })
    }
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{
        Address, Constraint, EdgeRef, GraphArg, GraphNode, ManifestGraph, Value,
    };

    use super::{BuildError, GraphBuilder, Param};

    const ALICE: Address = Address([0x10; 16]);
    const BOB: Address = Address([0x20; 16]);
    const RES: Address = Address([0xE1; 16]);

    #[test]
    fn a_transfer_builds_the_hand_written_graph() {
        let mut b = GraphBuilder::new();
        let [funds] = b.call(ALICE, "withdraw", (RES, 100u128));
        let [] = b.call(BOB, "deposit", (funds.resource_is(RES).min(1),));
        assert_eq!(
            b.build(),
            Ok(ManifestGraph {
                nodes: vec![
                    GraphNode {
                        target: ALICE,
                        method: "withdraw".into(),
                        args: vec![
                            GraphArg::Literal(Value::Address(RES)),
                            GraphArg::Literal(Value::U128(100)),
                        ],
                    },
                    GraphNode {
                        target: BOB,
                        method: "deposit".into(),
                        args: vec![GraphArg::Edge {
                            edge: EdgeRef {
                                producer: 0,
                                output: 0,
                            },
                            constraints: vec![
                                Constraint::ResourceIs(RES),
                                Constraint::MinAmount(1)
                            ],
                        }],
                    },
                ],
            })
        );
    }

    #[test]
    fn a_dropped_output_is_a_dangling_edge() {
        let mut b = GraphBuilder::new();
        let [_funds] = b.call(ALICE, "withdraw", (RES, 100u128));
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
        let [funds] = b.call(ALICE, "withdraw", (RES, 100u128));
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
        let [funds] = b.call(ALICE, "withdraw", (RES, 100u128));
        let _ = b.export(funds.min(1));
    }

    #[test]
    #[should_panic(expected = "the builder that minted it")]
    fn a_foreign_bucket_is_refused() {
        let mut minting = GraphBuilder::new();
        let [funds] = minting.call(ALICE, "withdraw", (RES, 100u128));
        let mut other = GraphBuilder::new();
        #[allow(
            clippy::tuple_array_conversions,
            reason = "the tuple is an argument list, not a conversion"
        )]
        let [] = other.call(BOB, "deposit", (funds,));
    }
}
