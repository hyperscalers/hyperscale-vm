//! Value crossing a shard boundary: what an execution issued, what it
//! took, and which of a manifest's nodes it ran at all.
//!
//! An execution that runs a subset of a manifest takes the rest as
//! attested value. Two facts follow it out: the totals, which the
//! conservation fold weighs, and the per-edge record, which is what a
//! certificate attests so the consuming shard claims *its own* argument
//! rather than a share of a sum.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::CrossingSite;
use hyperscale_vm_types::{MAX_CROSSINGS_PER_TX, ResourceAddr, SubstateKey};

use crate::modes::ModeError;

/// What one value edge carried across a boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Crossed {
    /// The resource that moved.
    pub resource: ResourceAddr,
    /// How much of it.
    pub amount: u128,
}

/// What one execution escrowed out and claimed in.
///
/// Beside [`SupplyDelta`](crate::SupplyDelta) on the receipt and never
/// inside it: folding a crossing into supply would record a mint that
/// never happened. What the two share is the fold that weighs them —
/// value leaving this execution had to come from somewhere, which is why
/// an issue is a gain there for the reason a burn is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EscrowDelta {
    issued: BTreeMap<ResourceAddr, u128>,
    claimed: BTreeMap<ResourceAddr, u128>,
    issued_at: BTreeMap<(u32, u32), Crossed>,
}

impl EscrowDelta {
    /// Whether this execution crossed anything at all.
    ///
    /// Read off the per-edge record rather than off the totals, because a
    /// zero-amount edge crosses: it writes a record cell and the consumer
    /// waits on a bundle naming it, so an execution that issued only
    /// zeroes has still issued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issued_at.is_empty() && self.claimed.is_empty()
    }

    /// What this execution escrowed out of a resource.
    #[must_use]
    pub fn issued(&self, resource: ResourceAddr) -> u128 {
        self.issued.get(&resource).copied().unwrap_or(0)
    }

    /// What this execution claimed in of a resource.
    #[must_use]
    pub fn claimed(&self, resource: ResourceAddr) -> u128 {
        self.claimed.get(&resource).copied().unwrap_or(0)
    }

    /// Every resource this execution crossed, ascending and once each.
    ///
    /// Merged rather than chained, on [`SupplyDelta::resources`]'s terms:
    /// a resource issued on one edge and claimed on another is one
    /// resource, and a caller folding per resource would otherwise weigh
    /// its halves twice.
    ///
    /// [`SupplyDelta::resources`]: crate::SupplyDelta::resources
    pub fn resources(&self) -> impl Iterator<Item = ResourceAddr> + '_ {
        let mut crossed: BTreeSet<ResourceAddr> = self.issued.keys().copied().collect();
        crossed.extend(self.claimed.keys().copied());
        crossed.into_iter()
    }

    /// What each departing edge carried, in `(node, output)` order.
    ///
    /// This is what a certificate attests. Per edge and not per resource,
    /// because a sum leaves two edges carrying one resource with no way
    /// to say which value fed which consumer.
    pub fn issues(&self) -> impl Iterator<Item = ((u32, u32), Crossed)> + '_ {
        self.issued_at
            .iter()
            .map(|(edge, crossed)| (*edge, *crossed))
    }

    /// Record what one edge sent.
    ///
    /// **A zero-amount edge records the edge while the totals skip it.**
    /// The record cell and the consumer's claim derive from the manifest
    /// edge, so an attestation that dropped a zero would leave the
    /// consumer waiting on a bundle whose target set the certificate
    /// never named.
    ///
    /// # Errors
    ///
    /// [`ModeError::EscrowOverflow`] on overflow, or past
    /// [`MAX_CROSSINGS_PER_TX`] — the bound is the kernel's own and not
    /// only the classifier's, because a plan reaching here has crossed a
    /// crate boundary since anything checked it.
    pub fn issue(&mut self, node: u32, output: u32, crossed: Crossed) -> Result<(), ModeError> {
        if self.issued_at.len() >= MAX_CROSSINGS_PER_TX
            && !self.issued_at.contains_key(&(node, output))
        {
            return Err(ModeError::EscrowOverflow);
        }
        self.issued_at.insert((node, output), crossed);
        Self::add(&mut self.issued, crossed.resource, crossed.amount)
    }

    /// Record what this execution took in.
    ///
    /// Per resource and not per edge: what the consumer owes the fold is
    /// the amount, and which edge it arrived on is the claim cell's to
    /// say.
    ///
    /// # Errors
    ///
    /// [`ModeError::EscrowOverflow`] on overflow.
    pub fn claim(&mut self, crossed: Crossed) -> Result<(), ModeError> {
        Self::add(&mut self.claimed, crossed.resource, crossed.amount)
    }

    fn add(
        into: &mut BTreeMap<ResourceAddr, u128>,
        resource: ResourceAddr,
        amount: u128,
    ) -> Result<(), ModeError> {
        if amount == 0 {
            return Ok(());
        }
        let slot = into.entry(resource).or_insert(0);
        *slot = slot.checked_add(amount).ok_or(ModeError::EscrowOverflow)?;
        Ok(())
    }
}

/// One edge leaving this execution: the record cell it writes, and the
/// cell the value left, which the record names so a reclaim can credit
/// it from the cell alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Departure {
    /// The record cell, under the producing node's target.
    pub site: CrossingSite,
    /// The cell the departing value was reserved from, where the edge is
    /// one a reclaim may take back — an inbound leg's. A core's edge
    /// names none: what it sends was minted or drawn from several cells,
    /// and a core that committed is never reclaimed from.
    pub origin: Option<SubstateKey>,
}

/// One crossing this execution takes back: the record the producing
/// shard wrote, claimed under the producer's own target.
///
/// Everything else a reclaim needs — the resource, the amount, the cell
/// to credit — is read off the record itself, so a shard holding nothing
/// but its own prefix can reclaim from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reclaim {
    /// The record cell to read.
    pub record: SubstateKey,
    /// The claim cell the reclaim writes, under the producer's target.
    pub claim: CrossingSite,
}

/// Which of a manifest's nodes this execution runs, and the cells the
/// ones it does not run stand in for.
///
/// Built by the parent from the frozen classification and the arrivals it
/// holds, never derived here: two shards divide one manifest separately
/// and their answers have to agree, or a crossing is issued that nobody
/// claims.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegPlan {
    skipped: BTreeSet<u32>,
    inbound: BTreeMap<(u32, u32), Crossed>,
    outbound: BTreeMap<(u32, u32), Departure>,
    claimed: BTreeMap<(u32, u32), CrossingSite>,
    reclaimed: BTreeMap<(u32, u32), Reclaim>,
}

impl LegPlan {
    /// The plan every execution runs until a transaction decomposes:
    /// nothing skipped, nothing crossing.
    #[must_use]
    pub fn whole() -> Self {
        Self::default()
    }

    /// Whether this execution invokes `node` itself.
    #[must_use]
    pub fn runs(&self, node: u32) -> bool {
        !self.skipped.contains(&node)
    }

    /// Whether this plan divides the manifest at all.
    #[must_use]
    pub fn is_whole(&self) -> bool {
        self.skipped.is_empty()
    }

    /// What arrived for the edge a skipped producer would have made.
    #[must_use]
    pub fn arrival(&self, node: u32, output: u32) -> Option<Crossed> {
        self.inbound.get(&(node, output)).copied()
    }

    /// The record cell an edge leaving this execution writes, and the
    /// cell the value left.
    #[must_use]
    pub fn departing(&self, node: u32, output: u32) -> Option<Departure> {
        self.outbound.get(&(node, output)).copied()
    }

    /// The crossings this execution takes back rather than runs, in
    /// `(node, output)` order: the producing node claiming its own
    /// record.
    pub fn reclaimed(&self) -> impl Iterator<Item = ((u32, u32), Reclaim)> + '_ {
        self.reclaimed
            .iter()
            .map(|(edge, reclaim)| (*edge, *reclaim))
    }

    /// The claim cell an arrival writes.
    #[must_use]
    pub fn claim(&self, node: u32, output: u32) -> Option<CrossingSite> {
        self.claimed.get(&(node, output)).copied()
    }

    /// Every record cell this execution writes, in edge order.
    pub fn records(&self) -> impl Iterator<Item = SubstateKey> + '_ {
        self.outbound.values().map(|departure| departure.site.key())
    }

    /// Every claim cell this execution writes, in edge order: the
    /// arrivals it takes, then the crossings it takes back.
    pub fn claims(&self) -> impl Iterator<Item = SubstateKey> + '_ {
        self.claimed
            .values()
            .map(CrossingSite::key)
            .chain(self.reclaimed.values().map(|reclaim| reclaim.claim.key()))
    }

    /// Mark a node as one another shard runs.
    pub fn skip(&mut self, node: u32) {
        self.skipped.insert(node);
    }

    /// File what arrives for one edge, and the claim cell taking it
    /// writes.
    ///
    /// # Errors
    ///
    /// [`PlanTooWide`] past [`MAX_CROSSINGS_PER_TX`].
    pub fn arrives(
        &mut self,
        node: u32,
        output: u32,
        crossed: Crossed,
        claim: CrossingSite,
    ) -> Result<(), PlanTooWide> {
        Self::bounded(&mut self.inbound, (node, output), crossed)?;
        Self::bounded(&mut self.claimed, (node, output), claim)
    }

    /// File the record cell one departing edge writes, and the cell the
    /// value leaves from.
    ///
    /// # Errors
    ///
    /// [`PlanTooWide`] past [`MAX_CROSSINGS_PER_TX`].
    pub fn departs(
        &mut self,
        node: u32,
        output: u32,
        record: CrossingSite,
        origin: Option<SubstateKey>,
    ) -> Result<(), PlanTooWide> {
        Self::bounded(
            &mut self.outbound,
            (node, output),
            Departure {
                site: record,
                origin,
            },
        )
    }

    /// File one crossing this execution takes back.
    ///
    /// # Errors
    ///
    /// [`PlanTooWide`] past [`MAX_CROSSINGS_PER_TX`].
    pub fn reclaims(
        &mut self,
        node: u32,
        output: u32,
        reclaim: Reclaim,
    ) -> Result<(), PlanTooWide> {
        Self::bounded(&mut self.reclaimed, (node, output), reclaim)
    }

    fn bounded<T>(
        into: &mut BTreeMap<(u32, u32), T>,
        edge: (u32, u32),
        value: T,
    ) -> Result<(), PlanTooWide> {
        if into.len() >= MAX_CROSSINGS_PER_TX && !into.contains_key(&edge) {
            return Err(PlanTooWide);
        }
        into.insert(edge, value);
        Ok(())
    }
}

/// A plan naming more crossings than one outcome can state a verdict for.
///
/// Bounded here and not only where the classifier refuses the shape,
/// because the plan reaches the kernel across a crate boundary and
/// nothing between them re-asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a leg plan may name at most {MAX_CROSSINGS_PER_TX} crossings")]
pub struct PlanTooWide;

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{Hash32, SubintentHash, TestHasher};
    use hyperscale_vm_types::ResourceAddr;

    use super::{Crossed, CrossingSite, EscrowDelta, LegPlan, MAX_CROSSINGS_PER_TX, ModeError};

    fn resource(tag: u8) -> ResourceAddr {
        ResourceAddr::new([tag; 31])
    }

    fn cell(tag: u8) -> CrossingSite {
        CrossingSite::record(
            &TestHasher,
            resource(tag),
            SubintentHash(Hash32([tag; 32])),
            0,
            0,
            1_000,
        )
    }

    fn crossed(tag: u8, amount: u128) -> Crossed {
        Crossed {
            resource: resource(tag),
            amount,
        }
    }

    /// The two sides are separate facts, and a resource crossing both
    /// ways is one resource — so a fold over `resources` weighs its
    /// halves once.
    #[test]
    fn the_two_sides_stay_apart_and_the_keys_merge() {
        let mut escrow = EscrowDelta::default();
        escrow.issue(0, 0, crossed(1, 40)).expect("fits");
        escrow.claim(crossed(1, 15)).expect("fits");
        escrow.claim(crossed(2, 7)).expect("fits");

        assert_eq!(escrow.issued(resource(1)), 40);
        assert_eq!(escrow.claimed(resource(1)), 15);
        assert_eq!(escrow.issued(resource(2)), 0);
        assert_eq!(
            escrow.resources().collect::<Vec<_>>(),
            vec![resource(1), resource(2)],
        );
    }

    /// A zero-amount edge crosses: the record cell and the consumer's
    /// claim derive from the manifest edge, so an attestation that
    /// dropped one would leave the consumer waiting on a bundle whose
    /// target set the certificate never named.
    #[test]
    fn a_zero_amount_edge_is_still_an_issue() {
        let mut escrow = EscrowDelta::default();
        escrow.issue(3, 1, crossed(1, 0)).expect("fits");

        assert!(!escrow.is_empty(), "the edge crossed");
        assert_eq!(escrow.issued(resource(1)), 0, "and the totals skip it");
        assert_eq!(
            escrow.issues().collect::<Vec<_>>(),
            vec![((3, 1), crossed(1, 0))],
        );
        assert_eq!(escrow.resources().count(), 0, "a zero moves no resource");
    }

    /// Past the cap the fold refuses rather than growing, because a plan
    /// reaching the kernel crossed a crate boundary since anything
    /// checked its width.
    #[test]
    fn the_crossing_cap_binds_the_fold() {
        let mut escrow = EscrowDelta::default();
        for edge in 0..MAX_CROSSINGS_PER_TX {
            let node = u32::try_from(edge).expect("bounded");
            escrow
                .issue(node, 0, crossed(1, 1))
                .expect("inside the cap");
        }
        let past = u32::try_from(MAX_CROSSINGS_PER_TX).expect("bounded");
        assert_eq!(
            escrow.issue(past, 0, crossed(1, 1)),
            Err(ModeError::EscrowOverflow),
        );
        // Re-recording an edge already named is not a new crossing.
        assert!(escrow.issue(0, 0, crossed(1, 2)).is_ok());
    }

    /// Summing what left is the fold's own arithmetic, and a failed sum
    /// is a refusal rather than a saturation that would read as
    /// agreement.
    #[test]
    fn an_overflowing_total_refuses() {
        let mut escrow = EscrowDelta::default();
        escrow.issue(0, 0, crossed(1, u128::MAX)).expect("fits");
        assert_eq!(
            escrow.issue(1, 0, crossed(1, 1)),
            Err(ModeError::EscrowOverflow),
        );
    }

    /// The plan every execution runs until a transaction decomposes.
    #[test]
    fn a_whole_plan_runs_every_node_and_crosses_nothing() {
        let plan = LegPlan::whole();
        assert!(plan.is_whole());
        assert!(plan.runs(0) && plan.runs(4_095));
        assert_eq!(plan.arrival(0, 0), None);
        assert_eq!(plan.departing(0, 0), None);
    }

    /// A skipped node is one another shard runs, and what stands in for
    /// it is the arrival filed against its own edge.
    #[test]
    fn a_divided_plan_names_what_it_does_not_run() {
        let mut plan = LegPlan::whole();
        plan.skip(1);
        plan.arrives(1, 0, crossed(1, 50), cell(9)).expect("fits");
        plan.departs(2, 0, cell(8), Some(cell(8).key()))
            .expect("fits");

        assert!(!plan.is_whole());
        assert!(!plan.runs(1));
        assert!(plan.runs(2));
        assert_eq!(plan.arrival(1, 0), Some(crossed(1, 50)));
        assert_eq!(plan.claim(1, 0), Some(cell(9)));
        assert_eq!(
            plan.departing(2, 0).map(|departure| departure.site),
            Some(cell(8))
        );
        assert_eq!(plan.arrival(1, 1), None, "another output is another edge");
    }

    /// The plan is bounded where it is built, not only where it is
    /// classified.
    #[test]
    fn a_plan_past_the_cap_refuses() {
        let mut plan = LegPlan::whole();
        for edge in 0..MAX_CROSSINGS_PER_TX {
            let node = u32::try_from(edge).expect("bounded");
            plan.departs(node, 0, cell(1), Some(cell(1).key()))
                .expect("inside the cap");
        }
        let past = u32::try_from(MAX_CROSSINGS_PER_TX).expect("bounded");
        assert!(plan.departs(past, 0, cell(1), Some(cell(1).key())).is_err());
        assert!(
            plan.departs(0, 0, cell(2), Some(cell(2).key())).is_ok(),
            "not a new crossing"
        );
    }
}
