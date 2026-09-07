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
    /// What each departing edge carried. The per-resource total is a
    /// fold over this, never a second figure that could disagree.
    issued_at: BTreeMap<(u32, u32), Crossed>,
    claimed: BTreeMap<ResourceAddr, u128>,
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

    /// What this execution escrowed out of a resource: the fold over
    /// every edge that carried it. Each issue checked the fold as it
    /// entered, so the sum fits.
    #[must_use]
    pub fn issued(&self, resource: ResourceAddr) -> u128 {
        self.issued_at
            .values()
            .filter(|crossed| crossed.resource == resource)
            .fold(0u128, |total, crossed| total.saturating_add(crossed.amount))
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
        let mut crossed: BTreeSet<ResourceAddr> = self
            .issued_at
            .values()
            .filter(|crossed| crossed.amount > 0)
            .map(|crossed| crossed.resource)
            .collect();
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
    /// One issue per edge and at most [`MAX_CROSSINGS_PER_TX`] of them
    /// are the plan's to hold: a [`LegPlan`] files one action per edge
    /// and refuses a plan past the cap, and the walk issues exactly what
    /// the plan departs.
    ///
    /// # Errors
    ///
    /// [`ModeError::EscrowOverflow`] where the resource's total would
    /// leave `u128`.
    pub fn issue(&mut self, node: u32, output: u32, crossed: Crossed) -> Result<(), ModeError> {
        self.issued(crossed.resource)
            .checked_add(crossed.amount)
            .ok_or(ModeError::EscrowOverflow)?;
        self.issued_at.insert((node, output), crossed);
        Ok(())
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
/// claim cell that would say the crossing was taken.
///
/// Both are the parent's to name. The record sits under the producing
/// node's target and the claim under the consuming node's, so only a
/// reader of the manifest can pair them — and the record carries the
/// pairing forward, since what outlives the manifest is the leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Departure {
    /// The record cell, under the producing node's target.
    pub site: CrossingSite,
    /// The claim cell the consumer writes when it takes the crossing,
    /// under the consuming node's target.
    pub consumer_claim: SubstateKey,
}

/// One record this execution settles rather than runs a node for: a
/// crossing the producing shard issued, either taken back or retired.
///
/// The record is read and deleted either way. Taken back, its resource
/// and amount are credited to the cell the value left and a claim is
/// written under the producer's own target, on the machinery a consumer
/// claims with; retired, nothing moves, since the consumer's committed
/// claim moved the value where it ran. Every term is the leaf's, so a
/// replica holding the prefix and nothing else — a split child —
/// composes a settlement from the record alone.
///
/// Evidence for either is the parent's to establish. What the kernel
/// checks is that the record is there and names the edge the claim site
/// names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disposal {
    /// The record cell to read.
    pub record: SubstateKey,
    /// The claim cell for the record's edge, under the producer's own
    /// target: written by a reclaim, and the site that says which edge a
    /// retirement holds the record to.
    pub claim: CrossingSite,
    /// What the settlement does with the record.
    pub disposition: Disposition,
}

/// What a settlement does with a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// No consumer claimed: credit the value back and claim the edge
    /// under the producer's own target.
    Reclaim,
    /// The consumer's claim committed: delete the record and move
    /// nothing.
    Retire,
}

/// What arrived for the edge a node this execution does not run would
/// have made: what crossed, and the claim cell taking it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrival {
    /// What the producing shard escrowed on this edge.
    pub crossed: Crossed,
    /// The claim cell the execution taking it writes.
    pub claim: CrossingSite,
}

/// What this execution does with one of a manifest's nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NodeAction {
    /// Invoked here.
    #[default]
    Run,
    /// Another shard runs it. What stands in for it is whatever crossed
    /// on its outputs.
    Elsewhere,
}

/// What this execution does at one value edge.
///
/// One action per edge, so the two are exclusive because there is one
/// slot to hold them rather than because two collections agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeAction {
    /// The producer ran here and its consumer runs elsewhere: the value
    /// leaves, into the record cell named.
    Departs(Departure),
    /// The producer runs elsewhere: what crossed to stand in for it.
    Arrives(Arrival),
}

/// Which of a manifest's nodes this execution runs, and what happens at
/// each of the edges between them.
///
/// One entry per node and one per edge: "runs here" is a position in the
/// node vector and "arrives here" is one action in the edge map, so
/// neither can be stated twice and no two collections have to agree.
///
/// Built by the parent from the frozen classification and the arrivals it
/// holds, never derived here: two shards divide one manifest separately
/// and their answers have to agree, or a crossing is issued that nobody
/// claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegPlan {
    /// One action per manifest node, in index order. A node past the
    /// end runs: a plan shorter than the manifest divides nothing of
    /// what it does not name, which is what an entry that never filed
    /// one is.
    nodes: Vec<NodeAction>,
    edges: BTreeMap<(u32, u32), EdgeAction>,
}

impl LegPlan {
    /// The plan every execution runs until a transaction decomposes:
    /// every one of `nodes` invoked here, nothing crossing.
    ///
    /// The arity is the manifest's, and it is what makes a node past the
    /// manifest a refusal where the plan is built rather than a silent
    /// entry nothing reads.
    #[must_use]
    pub fn whole(nodes: usize) -> Self {
        Self {
            nodes: vec![NodeAction::Run; nodes],
            edges: BTreeMap::new(),
        }
    }

    /// Whether this execution invokes `node` itself.
    #[must_use]
    pub fn runs(&self, node: u32) -> bool {
        self.action(node) == NodeAction::Run
    }

    /// Whether this plan divides the manifest at all.
    #[must_use]
    pub fn is_whole(&self) -> bool {
        self.nodes.iter().all(|action| *action == NodeAction::Run)
    }

    /// What arrived for the edge a node another shard runs would have
    /// made.
    #[must_use]
    pub fn arrival(&self, node: u32, output: u32) -> Option<Arrival> {
        match self.edges.get(&(node, output)) {
            Some(EdgeAction::Arrives(arrival)) => Some(*arrival),
            _ => None,
        }
    }

    /// The record cell an edge leaving this execution writes.
    #[must_use]
    pub fn departure(&self, node: u32, output: u32) -> Option<Departure> {
        match self.edges.get(&(node, output)) {
            Some(EdgeAction::Departs(departure)) => Some(*departure),
            _ => None,
        }
    }

    /// Every record cell this execution writes, in edge order.
    pub fn records(&self) -> impl Iterator<Item = SubstateKey> + '_ {
        self.edges.values().filter_map(|action| match action {
            EdgeAction::Departs(departure) => Some(departure.site.key()),
            EdgeAction::Arrives(_) => None,
        })
    }

    /// Every claim cell this execution writes, in edge order: the
    /// arrivals it takes.
    pub fn claims(&self) -> impl Iterator<Item = SubstateKey> + '_ {
        self.edges.values().filter_map(|action| match action {
            EdgeAction::Arrives(arrival) => Some(arrival.claim.key()),
            EdgeAction::Departs(_) => None,
        })
    }

    /// Mark a node as one another shard runs.
    ///
    /// # Errors
    ///
    /// [`PlanFault::NoSuchNode`] past the manifest the plan was sized to.
    pub fn skip(&mut self, node: u32) -> Result<(), PlanFault> {
        *self.slot(node)? = NodeAction::Elsewhere;
        Ok(())
    }

    /// File what arrives for one edge, and the claim cell taking it
    /// writes.
    ///
    /// # Errors
    ///
    /// [`PlanFault`]: a node past the manifest, an edge already acted on,
    /// an arrival for a node this execution runs itself, or a plan past
    /// [`MAX_CROSSINGS_PER_TX`].
    pub fn arrives(
        &mut self,
        node: u32,
        output: u32,
        crossed: Crossed,
        claim: CrossingSite,
    ) -> Result<(), PlanFault> {
        if self.action(node) == NodeAction::Run {
            return Err(PlanFault::ArrivesHere { node, output });
        }
        self.act(
            node,
            output,
            EdgeAction::Arrives(Arrival { crossed, claim }),
        )
    }

    /// File the record cell one departing edge writes.
    ///
    /// # Errors
    ///
    /// [`PlanFault`]: a node past the manifest, an edge already acted on,
    /// a departure from a node this execution does not run, or a plan
    /// past [`MAX_CROSSINGS_PER_TX`].
    pub fn departs(
        &mut self,
        node: u32,
        output: u32,
        departure: Departure,
    ) -> Result<(), PlanFault> {
        if self.action(node) == NodeAction::Elsewhere {
            return Err(PlanFault::DepartsElsewhere { node, output });
        }
        self.act(node, output, EdgeAction::Departs(departure))
    }

    /// The node's action. A node past the manifest runs, which is what
    /// an unnamed one has always been.
    fn action(&self, node: u32) -> NodeAction {
        self.nodes
            .get(node as usize)
            .copied()
            .unwrap_or(NodeAction::Run)
    }

    fn slot(&mut self, node: u32) -> Result<&mut NodeAction, PlanFault> {
        self.nodes
            .get_mut(node as usize)
            .ok_or(PlanFault::NoSuchNode { node })
    }

    /// File `action` at one edge, which must be free: a second action on
    /// one edge is two answers to what happens to one value.
    fn act(&mut self, node: u32, output: u32, action: EdgeAction) -> Result<(), PlanFault> {
        if self.nodes.get(node as usize).is_none() {
            return Err(PlanFault::NoSuchNode { node });
        }
        if self.edges.contains_key(&(node, output)) {
            return Err(PlanFault::EdgeTwice { node, output });
        }
        if self.edges.len() >= MAX_CROSSINGS_PER_TX {
            return Err(PlanFault::TooWide);
        }
        self.edges.insert((node, output), action);
        Ok(())
    }
}

/// What a plan cannot say about itself.
///
/// Checked here and not only where the classifier refuses the shape,
/// because the plan reaches the kernel across a crate boundary and
/// nothing between them re-asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanFault {
    /// A node the manifest the plan was sized to does not have.
    #[error("node {node} is past the manifest")]
    NoSuchNode {
        /// The index named.
        node: u32,
    },
    /// Two actions at one edge.
    #[error("edge ({node}, {output}) already has an action")]
    EdgeTwice {
        /// The producing node.
        node: u32,
        /// Which of its outputs.
        output: u32,
    },
    /// An arrival for a node this execution invokes itself: what the
    /// node produces is what it returns, and nothing crosses to it.
    #[error("edge ({node}, {output}) arrives for a node this execution runs")]
    ArrivesHere {
        /// The producing node.
        node: u32,
        /// Which of its outputs.
        output: u32,
    },
    /// A departure from a node this execution does not run: value can
    /// only leave an execution that produced it.
    #[error("edge ({node}, {output}) departs a node this execution does not run")]
    DepartsElsewhere {
        /// The producing node.
        node: u32,
        /// Which of its outputs.
        output: u32,
    },
    /// More crossings than one outcome can state a verdict for.
    #[error("a leg plan may name at most {MAX_CROSSINGS_PER_TX} crossings")]
    TooWide,
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{Hash32, SubintentHash, TestHasher};
    use hyperscale_vm_types::ResourceAddr;

    use super::{
        Arrival, Crossed, CrossingSite, Departure, EscrowDelta, LegPlan, MAX_CROSSINGS_PER_TX,
        ModeError, PlanFault,
    };

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

    fn departing(tag: u8) -> Departure {
        Departure {
            site: cell(tag),
            consumer_claim: cell(tag.wrapping_add(1)).key(),
        }
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
        let plan = LegPlan::whole(3);
        assert!(plan.is_whole());
        assert!(plan.runs(0) && plan.runs(2));
        assert_eq!(plan.arrival(0, 0), None);
        assert_eq!(plan.departure(0, 0), None);
    }

    /// A skipped node is one another shard runs, and what stands in for
    /// it is the arrival filed against its own edge.
    #[test]
    fn a_divided_plan_names_what_it_does_not_run() {
        let mut plan = LegPlan::whole(3);
        plan.skip(1).expect("inside the manifest");
        plan.arrives(1, 0, crossed(1, 50), cell(9)).expect("fits");
        plan.departs(2, 0, departing(8)).expect("fits");

        assert!(!plan.is_whole());
        assert!(!plan.runs(1));
        assert!(plan.runs(2));
        assert_eq!(
            plan.arrival(1, 0),
            Some(Arrival {
                crossed: crossed(1, 50),
                claim: cell(9),
            }),
        );
        assert_eq!(plan.departure(2, 0), Some(departing(8)));
        assert_eq!(plan.arrival(1, 1), None, "another output is another edge");
    }

    /// One edge, one action: a second answer to what happens to one
    /// value is refused rather than overwriting the first.
    #[test]
    fn an_edge_takes_one_action() {
        let mut plan = LegPlan::whole(2);
        plan.departs(0, 0, departing(1)).expect("fits");
        assert_eq!(
            plan.departs(0, 0, departing(2)),
            Err(PlanFault::EdgeTwice { node: 0, output: 0 }),
        );
        plan.skip(1).expect("inside the manifest");
        plan.arrives(1, 0, crossed(1, 5), cell(3)).expect("fits");
        assert_eq!(
            plan.arrives(1, 0, crossed(1, 6), cell(4)),
            Err(PlanFault::EdgeTwice { node: 1, output: 0 }),
        );
    }

    /// Value leaves the execution that produced it and arrives for one
    /// that did not, so neither can be filed against the other's node.
    #[test]
    fn an_edge_agrees_with_the_node_it_hangs_off() {
        let mut plan = LegPlan::whole(2);
        assert_eq!(
            plan.arrives(0, 0, crossed(1, 5), cell(9)),
            Err(PlanFault::ArrivesHere { node: 0, output: 0 }),
        );
        plan.skip(1).expect("inside the manifest");
        assert_eq!(
            plan.departs(1, 0, departing(8)),
            Err(PlanFault::DepartsElsewhere { node: 1, output: 0 }),
        );
    }

    /// A plan is sized to its manifest, so a node past it is refused
    /// where the plan is built rather than filed where nothing reads it.
    #[test]
    fn a_node_past_the_manifest_refuses() {
        let mut plan = LegPlan::whole(2);
        assert_eq!(plan.skip(2), Err(PlanFault::NoSuchNode { node: 2 }));
        assert_eq!(
            plan.departs(2, 0, departing(1)),
            Err(PlanFault::NoSuchNode { node: 2 }),
        );
    }

    /// The plan is bounded where it is built, not only where it is
    /// classified.
    #[test]
    fn a_plan_past_the_cap_refuses() {
        let mut plan = LegPlan::whole(MAX_CROSSINGS_PER_TX + 1);
        for edge in 0..MAX_CROSSINGS_PER_TX {
            let node = u32::try_from(edge).expect("bounded");
            plan.departs(node, 0, departing(1)).expect("inside the cap");
        }
        let past = u32::try_from(MAX_CROSSINGS_PER_TX).expect("bounded");
        assert_eq!(plan.departs(past, 0, departing(1)), Err(PlanFault::TooWide));
    }
}
