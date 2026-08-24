//! Per-shard supply accumulators: the linearity substrate.
//!
//! Aggregates are never global cells — each shard accumulates, per
//! resource, the total amount its cells hold. The accumulator changes only
//! on mint, burn, and cross-shard movement; same-shard transfers conserve
//! it by construction. Composition is per-resource addition, so splitting
//! and merging shards composes accumulators exactly — the reshape-clean
//! property the design demands of every stdlib accumulator.
//!
//! Supply is per-shard for auditability first and throughput second. A
//! global supply cell would not even contend — supply updates are
//! commutative, and the delta mode exists — but it would constrain
//! nothing: a shard fabricating balances for a resource homed elsewhere
//! never touches it, and the discrepancy is invisible without a global
//! scan. A per-shard accumulator's trajectory is bounded by public facts
//! — genesis, the shard's own authority-evidenced mints and burns, and
//! the attested supply delta on every cross-shard leg — so an external
//! verifier can audit how much value a shard is supposed to hold from
//! certificates alone. Fabricated value is loud instead of silent, and
//! the total is a fold that reshape preserves rather than a number
//! nobody can check.
//!
//! Two operations move it, and both carry a resource address because a
//! grant does: minting brings value into existence under the authority
//! over one resource, and burning takes it out under the same. A receipt
//! records what its transaction did as a [`SupplyDelta`], and a
//! committing transaction's delta is what a shard applies. An aborting
//! one has none.
//!
//! Nothing else moves it, and nothing else needs to. A transfer is a
//! debit and a credit on two cells holding the same resource, which sums
//! to zero however many cells it crosses — so same-shard movement
//! conserves the accumulator by construction rather than by counting.
//! What a cross-shard leg does to it is the settlement attestation's
//! answer, carried with the leg rather than derived here.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_types::ResourceAddr;

use crate::modes::ModeError;

/// What one transaction brought into and out of existence, per resource.
///
/// The receipt's own record of the two operations that move supply, kept
/// apart from the state delta because supply is not a cell: no key holds
/// it, and what changed it is the authority a grant conferred rather than
/// any write. A committing transaction's delta is applied to the shard's
/// ledger; an aborting one has none, on the same terms its events do not
/// survive.
///
/// Both halves rather than a net, because they are different facts: a
/// resource minted and burned in one transaction moved supply twice and
/// says so, where a net of zero would read as a transaction that touched
/// nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SupplyDelta {
    minted: BTreeMap<ResourceAddr, u128>,
    burned: BTreeMap<ResourceAddr, u128>,
}

impl SupplyDelta {
    /// Whether the transaction moved any supply at all.
    ///
    /// True of almost every transaction: a transfer conserves supply by
    /// construction, so only an authority-bearing one moves it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.minted.is_empty() && self.burned.is_empty()
    }

    /// What this transaction minted of a resource.
    #[must_use]
    pub fn minted(&self, resource: ResourceAddr) -> u128 {
        self.minted.get(&resource).copied().unwrap_or(0)
    }

    /// What this transaction burned of a resource.
    #[must_use]
    pub fn burned(&self, resource: ResourceAddr) -> u128 {
        self.burned.get(&resource).copied().unwrap_or(0)
    }

    /// Every resource this transaction moved, ascending and once each.
    ///
    /// A resource minted and burned in one transaction is in both maps
    /// and is still one resource, so the two key sets are merged rather
    /// than chained — a caller folding per resource would otherwise
    /// count such a resource's halves twice.
    pub fn resources(&self) -> impl Iterator<Item = ResourceAddr> + '_ {
        let mut moved: BTreeSet<ResourceAddr> = self.minted.keys().copied().collect();
        moved.extend(self.burned.keys().copied());
        moved.into_iter()
    }

    /// Record a mint.
    ///
    /// # Errors
    ///
    /// [`ModeError::SupplyOutOfBounds`] on overflow.
    pub fn mint(&mut self, resource: ResourceAddr, amount: u128) -> Result<(), ModeError> {
        Self::add(&mut self.minted, resource, amount)
    }

    /// Record a burn.
    ///
    /// # Errors
    ///
    /// [`ModeError::SupplyOutOfBounds`] on overflow.
    pub fn burn(&mut self, resource: ResourceAddr, amount: u128) -> Result<(), ModeError> {
        Self::add(&mut self.burned, resource, amount)
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
        *slot = slot
            .checked_add(amount)
            .ok_or(ModeError::SupplyOutOfBounds)?;
        Ok(())
    }

    /// Move a shard's accumulator by what this transaction did.
    ///
    /// # Errors
    ///
    /// [`ModeError::SupplyOutOfBounds`] on overflow, or on a burn past
    /// what the shard accumulated — which is a shard destroying value it
    /// never held, and so a defect rather than a business condition.
    pub fn apply(&self, ledger: &mut SupplyLedger) -> Result<(), ModeError> {
        for (resource, amount) in &self.minted {
            ledger.credit(*resource, *amount)?;
        }
        for (resource, amount) in &self.burned {
            ledger.debit(*resource, *amount)?;
        }
        Ok(())
    }
}

/// A shard's per-resource supply accumulator.
///
/// Keyed by the type its writers carry: supply moves only under a grant,
/// and a grant names a minter, which the protocol resource does not have
/// — so a ledger keyed any wider would hold keys nothing can produce.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SupplyLedger {
    by_resource: BTreeMap<ResourceAddr, u128>,
}

impl SupplyLedger {
    /// An empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            by_resource: BTreeMap::new(),
        }
    }

    /// The accumulated amount for a resource; zero when untracked.
    #[must_use]
    pub fn amount(&self, resource: ResourceAddr) -> u128 {
        self.by_resource.get(&resource).copied().unwrap_or(0)
    }

    /// Credit a resource: mint or inbound cross-shard movement.
    ///
    /// # Errors
    ///
    /// [`ModeError::SupplyOutOfBounds`] on overflow.
    pub fn credit(&mut self, resource: ResourceAddr, amount: u128) -> Result<(), ModeError> {
        let total = self
            .amount(resource)
            .checked_add(amount)
            .ok_or(ModeError::SupplyOutOfBounds)?;
        self.set(resource, total);
        Ok(())
    }

    /// Debit a resource: burn or outbound cross-shard movement.
    ///
    /// # Errors
    ///
    /// [`ModeError::SupplyOutOfBounds`] if the debit exceeds the
    /// accumulated amount.
    pub fn debit(&mut self, resource: ResourceAddr, amount: u128) -> Result<(), ModeError> {
        let total = self
            .amount(resource)
            .checked_sub(amount)
            .ok_or(ModeError::SupplyOutOfBounds)?;
        self.set(resource, total);
        Ok(())
    }

    /// Records a resource's total in canonical form: a resource this shard
    /// holds none of is absent, never present at zero. Equality is over the
    /// map, and it is the reshape-clean property — two shards holding the
    /// same supply must compare equal however they arrived there, including
    /// through a zero-amount cross-shard leg.
    fn set(&mut self, resource: ResourceAddr, total: u128) {
        if total == 0 {
            self.by_resource.remove(&resource);
        } else {
            self.by_resource.insert(resource, total);
        }
    }

    /// Compose two ledgers by per-resource addition — the split/merge
    /// composition: composing two children yields exactly the parent.
    ///
    /// # Errors
    ///
    /// [`ModeError::SupplyOutOfBounds`] on overflow.
    pub fn compose(&self, other: &Self) -> Result<Self, ModeError> {
        let mut composed = self.clone();
        for (resource, amount) in &other.by_resource {
            composed.credit(*resource, *amount)?;
        }
        Ok(composed)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::ResourceAddr;

    use super::SupplyLedger;
    use crate::modes::ModeError;

    const fn resource(byte: u8) -> ResourceAddr {
        ResourceAddr::new([byte; 31])
    }

    #[test]
    fn credits_and_debits_are_checked() {
        let mut ledger = SupplyLedger::new();
        ledger.credit(resource(1), 100).unwrap();
        ledger.debit(resource(1), 40).unwrap();
        assert_eq!(ledger.amount(resource(1)), 60);
        assert_eq!(
            ledger.debit(resource(1), 61),
            Err(ModeError::SupplyOutOfBounds)
        );
        ledger.credit(resource(1), u128::MAX - 60).unwrap();
        assert_eq!(
            ledger.credit(resource(1), 1),
            Err(ModeError::SupplyOutOfBounds)
        );
    }

    #[test]
    fn composition_reassembles_the_parent_exactly() {
        let mut parent = SupplyLedger::new();
        parent.credit(resource(1), 1_000).unwrap();
        parent.credit(resource(2), 250).unwrap();

        // An arbitrary split of the parent's holdings across two children.
        let mut left = SupplyLedger::new();
        left.credit(resource(1), 731).unwrap();
        left.credit(resource(2), 250).unwrap();
        let mut right = SupplyLedger::new();
        right.credit(resource(1), 269).unwrap();

        assert_eq!(left.compose(&right).unwrap(), parent);
        // Composition commutes.
        assert_eq!(right.compose(&left).unwrap(), parent);
    }

    #[test]
    fn a_fully_debited_resource_leaves_no_residue() {
        let mut ledger = SupplyLedger::new();
        ledger.credit(resource(3), 10).unwrap();
        ledger.debit(resource(3), 10).unwrap();
        assert_eq!(ledger, SupplyLedger::new());
    }

    #[test]
    fn a_zero_credit_leaves_no_residue() {
        let mut ledger = SupplyLedger::new();
        ledger.credit(resource(4), 0).unwrap();
        assert_eq!(ledger.amount(resource(4)), 0);
        assert_eq!(ledger, SupplyLedger::new());

        // And composing a zero-amount leg is the identity, not a ledger
        // that merely reads as zero.
        let mut held = SupplyLedger::new();
        held.credit(resource(4), 9).unwrap();
        assert_eq!(held.compose(&ledger).unwrap(), held);
    }
}
