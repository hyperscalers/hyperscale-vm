//! Run a transaction whole against the state it declares, and report
//! what a receipt would say.
//!
//! Static access is what makes this possible: every cell and range a leg
//! touches is in the declaration, bounded by the widths and caps the fee
//! prices. So a preview never executes leg by leg across shards — it
//! reads the declared cells from whoever holds them, at one anchor per
//! shard, and runs every node in one process under whole-shape
//! locality. The meter pass makes the fuel identical wherever the module
//! runs, so the per-node figures are the ones production would charge
//! for the same state.
//!
//! # What it does not promise
//!
//! One snapshot per shard and no reservations, so it cannot predict a
//! lost race, a crossing outside its window, or a reshape fence: those
//! depend on other transactions, and a preview reads none of them. The
//! report is optimistic and says so in exactly that sense — it answers
//! what this transaction would do against state nobody else is touching.
//!
//! Value-dependent control flow can still drift between a preview and
//! the execution that follows it, which is what [`Slack`] is for: the
//! ceilings a report fills are the measured figures with a margin, and a
//! composer signs those.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_vm_effects::{Admitted, explain_refusal};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, ExecutionMode, GuestBackend, ManifestWalk, OwnerSet, Substates,
    execute_batch,
};
use hyperscale_vm_types::{
    Address, BASIS_POINTS, CollectionId, Event, Movement, Outcome, SubstateKey, TxHash,
    UnmetCondition,
};

/// How much room a filled ceiling leaves over what the preview measured.
///
/// A margin in basis points, because the figure it covers is a
/// measurement and the execution that follows it reads state the preview
/// did not: value-dependent control flow can take a longer path over a
/// balance that moved. A composer who signs the measured figure exactly
/// signs a transaction that traps on any drift at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slack(u32);

impl Slack {
    /// No room at all: the ceilings are the measured figures. For a
    /// caller pinning what a run cost rather than composing from it.
    pub const NONE: Self = Self(0);

    /// A quarter over the measurement, which is what a wallet composing
    /// against a balance it does not control wants.
    pub const GENEROUS: Self = Self(2_500);

    /// `bp` basis points of room over the measured figure.
    #[must_use]
    pub const fn of(bp: u32) -> Self {
        Self(bp)
    }

    /// `measured` with this margin over it, saturating.
    ///
    /// The margin widens into `u128` before it is added to, because
    /// [`of`](Self::of) takes any `u32` and a margin near the top of one
    /// would otherwise carry the sum away in the narrower type — leaving
    /// a ceiling *below* what the run was measured to spend, which is the
    /// one answer worse than refusing.
    #[must_use]
    pub const fn over(self, measured: u64) -> u64 {
        let raised =
            (measured as u128) * (BASIS_POINTS as u128 + self.0 as u128) / (BASIS_POINTS as u128);
        if raised > u64::MAX as u128 {
            u64::MAX
        } else {
            #[allow(clippy::cast_possible_truncation)] // guarded on the line above
            {
                raised as u64
            }
        }
    }
}

/// What a preview found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// How the run ended.
    pub outcome: Outcome,
    /// The refusal in the explain vocabulary, where the outcome was one
    /// a declaration's own condition refused. `None` for every other
    /// ending, including a trap — what a guest did to itself has no
    /// declaration to explain.
    pub refusal: Option<String>,
    /// What moved, per cell, in key order.
    ///
    /// Read under whole locality, because the report answers what the
    /// transaction does: which shard applies which part of it is a
    /// question about commitment, not about resources.
    pub movements: Vec<(SubstateKey, Movement)>,
    /// What settled against a reservation, per cell, as the debits they
    /// are. The other half of what moved: a reader adding one without
    /// the other reports a balance that never existed.
    pub settles: Vec<(SubstateKey, Movement)>,
    /// What the transaction said happened, in emission order.
    pub events: Vec<Event>,
    /// Fuel each node spent, in node order.
    pub spent: Vec<u64>,
    /// The ceiling each node's measurement asks for, in node order:
    /// [`Self::spent`] under the [`Slack`] the caller named. What a
    /// composer signs.
    pub ceilings: Vec<u64>,
}

impl Report {
    /// Whether the transaction completed.
    #[must_use]
    pub const fn completed(&self) -> bool {
        matches!(self.outcome, Outcome::Completed { .. })
    }

    /// What the ceilings sum to: what the envelope's compute term will
    /// be if the composer signs them.
    #[must_use]
    pub fn compute(&self) -> u64 {
        self.ceilings
            .iter()
            .fold(0u64, |total, node| total.saturating_add(*node))
    }
}

/// Run `entry` against `source` and report what a receipt would say.
///
/// `admitted` is the admitted form the entry was lowered from, which is
/// what a refusal is explained against — `None` where the caller holds
/// none, and a refused report then names the condition without the
/// prose. `hash` is the protocol hash the execution runs under, and
/// `backend` the engine that runs the bodies.
///
/// The entry is the caller's, built through the one seam the chain
/// builds it through, so a preview and the block that follows it meter
/// the same bounds: the signed ceilings, the event bounds, the clock and
/// the draw. What a preview changes is where the state comes from and
/// that nothing else is touching it.
#[must_use]
pub fn preview(
    entry: &BatchTx,
    admitted: Option<&Admitted>,
    source: Arc<dyn Substates>,
    backend: &dyn GuestBackend,
    hash: fn(&[u8]) -> [u8; 32],
    slack: Slack,
) -> Report {
    let outcome = execute_batch(
        Arc::new(Optimistic { source }) as Arc<dyn Baseline>,
        std::slice::from_ref(entry),
        &ManifestWalk { backend },
        hash,
        ExecutionMode::Serial,
    );
    let Ok(outcome) = outcome else {
        // The environment could not run a body — code this source cannot
        // resolve. Nothing about the transaction is known, so the report
        // says exactly that rather than reading as a refusal.
        return Report {
            outcome: Outcome::Completed {
                answers: Capped::empty(),
            },
            refusal: Some("the engine could not run this transaction's code".to_owned()),
            movements: Vec::new(),
            settles: Vec::new(),
            events: Vec::new(),
            spent: Vec::new(),
            ceilings: Vec::new(),
        };
    };
    let Some(receipt) = outcome.receipts.get(&entry.tx) else {
        return Report {
            outcome: Outcome::Completed {
                answers: Capped::empty(),
            },
            refusal: Some("the batch returned no receipt for this transaction".to_owned()),
            movements: Vec::new(),
            settles: Vec::new(),
            events: Vec::new(),
            spent: Vec::new(),
            ceilings: Vec::new(),
        };
    };
    let whole = OwnerSet::whole();
    let moved = receipt.delta.owned(&whole);
    Report {
        refusal: refusal_text(admitted, &receipt.outcome),
        movements: moved.movements().collect(),
        settles: moved.settles().collect(),
        events: receipt.events.clone(),
        ceilings: receipt
            .fuel_by_node
            .iter()
            .map(|node| slack.over(*node))
            .collect(),
        spent: receipt.fuel_by_node.clone(),
        outcome: receipt.outcome.clone(),
    }
}

/// The explain text for an outcome a declaration's own condition
/// refused, and nothing for any other ending.
fn refusal_text(admitted: Option<&Admitted>, outcome: &Outcome) -> Option<String> {
    match outcome {
        Outcome::ConditionUnmet { condition } => Some(admitted.map_or_else(
            || format!("a declared condition went unmet: {condition:?}"),
            |admitted| explain_refusal(admitted, condition),
        )),
        _ => None,
    }
}

/// A committed read with nothing reserved over it.
///
/// The optimism the module doc names, in one place: a preview holds no
/// other transaction's reservations because it can see none, so every
/// cell reads as free. What that costs is the lost race it cannot
/// predict, which is the trade a preview is.
struct Optimistic {
    source: Arc<dyn Substates>,
}

impl std::fmt::Debug for Optimistic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Optimistic").finish_non_exhaustive()
    }
}

impl Substates for Optimistic {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.source.cell(key)
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        self.source
            .entries_in_range(owner, collection, lo, hi, limit)
    }
}

impl Baseline for Optimistic {
    fn holds(&self, _key: SubstateKey) -> BTreeMap<TxHash, u128> {
        BTreeMap::new()
    }
}

/// An [`UnmetCondition`] re-exported for callers matching on a report's
/// outcome without depending on the effects crate directly.
pub type Unmet = UnmetCondition;
