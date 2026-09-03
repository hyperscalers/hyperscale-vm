//! Where a manifest's nodes sit in the star a decomposable transaction
//! takes the shape of, and the cells value crosses through.
//!
//! One home for the vocabulary. The classifier reads it, the bridge
//! derives it onto every transaction, and the planner divides a manifest
//! by it — so a variant one of them dropped would default the payer's
//! shard into every core set rather than fail to compile.

use hyperscale_hbor::Hbor;

use crate::address::{Address, SubstateKey};
use crate::envelope::SubintentHash;

/// Where a manifest node sits in the star.
///
/// The topology is one core with legs around it, and the leg kinds
/// differ by what they do to value: an inbound leg runs before the core
/// and hands it attested value, an outbound leg runs after and cannot
/// refuse what it is handed, an attesting leg moves none at all.
/// Everything else is core, which is what the transaction's atomicity has
/// to cover.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum LegRole {
    /// Runs before the core, on arguments the core did not produce, and
    /// commits locally: its refusal is the escrow release path rather
    /// than the core's problem.
    Inbound,
    /// Neither leg. The default in both senses — what a node is when
    /// nothing lets it decompose, and what the star is organised around.
    #[default]
    Core,
    /// Runs after the core and offers it no veto: nothing it does can
    /// come back as a refusal the core would have to answer.
    Outbound,
    /// Commits nothing. It reads, it proves, and the nodes presenting
    /// what it proved run beside it on its own shard — so it bears no
    /// part of the atomicity the core exists for, and joins the core only
    /// where nothing else would.
    Attesting,
}

/// One value edge, as the node consuming it sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct ValueEdge {
    /// The producing node's index.
    pub source: u32,
    /// Which of the producer's outputs it carries.
    pub output: u32,
    /// Whether the edge names instances rather than counting amounts.
    pub non_fungible: bool,
}

/// One manifest node's placement-free shape: where it sits, what it
/// consumes, whose authority it speaks on, what it declares, and which
/// signed intent it came from.
///
/// Everything here is fixed by the envelope. Which shard a target
/// resolves to is the one part a reshape can move, and it is read off a
/// placement at the anchor rather than carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegShape {
    /// The instance invoked, whose owner prefix fixes the node's shard.
    pub target: Address,
    /// Where the node sits before placement settles the attesting ones.
    pub role: LegRole,
    /// The value edges this node consumes, in argument order.
    pub edges: Vec<ValueEdge>,
    /// The subjects this node presents a claim on.
    ///
    /// The manifest resolved every evidence reference into a claim, so
    /// the producing node is no longer named — what is left is the
    /// subject, which is what the co-location question is about anyway.
    pub presents: Vec<Address>,
    /// The owners this node's frame declares, in declaration order.
    ///
    /// Per node rather than for the transaction: whether a node declares
    /// inside the scope of the member running it is a question the union
    /// declaration has already forgotten the answer to.
    pub declares: Vec<Address>,
    /// The signed intent this node belongs to.
    ///
    /// With `local`, what an escrow cell is keyed by: content one signer
    /// signed and a position inside it only that signer can move. The
    /// manifest index is the composer's interleave and is not this.
    pub intent: SubintentHash,
    /// The node's index within its own intent's graph.
    pub local: u32,
    /// When the cells this node's crossings write stop being owed: its
    /// intent's own window end plus the escrow grace — never the
    /// transaction's, which is the composer's to choose.
    pub expiry_ms: u64,
}

/// One value edge's record cell, and the cell the value would leave.
///
/// Derived for every value edge, not only the ones that turn out to
/// cross: which cross is a placement fact read at an anchor, while the
/// declaration is fixed when the envelope is composed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Crossing {
    /// The producing node.
    pub node: u32,
    /// Which of its outputs the edge carries.
    pub output: u32,
    /// The record cell, under the producing node's target.
    pub record: SubstateKey,
    /// The cell the value leaves from, which the record names so a
    /// reclaim can credit it from the leaf alone.
    ///
    /// The producing frame's one reserved cell, where it has exactly
    /// one — the shape an inbound leg takes, and the only producer whose
    /// record is ever reclaimed. A producer reserving nothing or several
    /// cells names no origin, and a plan cannot issue its edge.
    pub origin: Option<SubstateKey>,
}
