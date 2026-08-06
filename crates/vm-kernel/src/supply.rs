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
//! Nothing on the execution path moves the ledger, and nothing on it can:
//! every operation here takes a *resource address*, and the session's
//! floor has none to give. A queued delta lands on a cell whose key is a
//! hash — which resource it moved lives in the key material the manifest
//! layer chose and in the walk's typed edges, both above this crate — so
//! wiring conservation into `finish` is not a missing call, it is
//! inexpressible below the layer that knows resource identity. The ledger
//! moves with the operations that carry an address by construction: mint
//! and burn under resource authority, and cross-shard settlement, whose
//! attestation carries each leg's supply delta. Until those operations
//! exist, conservation is unenforced — a guest returning a bucket it
//! never debited mints from nothing — and what this module holds correct,
//! under the conservation suite, is the substrate they will land on.

use std::collections::BTreeMap;

use hyperscale_vm_effects::Address;

use crate::modes::ModeError;

/// A shard's per-resource supply accumulator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SupplyLedger {
    by_resource: BTreeMap<Address, u128>,
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
    pub fn amount(&self, resource: Address) -> u128 {
        self.by_resource.get(&resource).copied().unwrap_or(0)
    }

    /// Credit a resource: mint or inbound cross-shard movement.
    ///
    /// # Errors
    ///
    /// [`ModeError::SupplyOutOfBounds`] on overflow.
    pub fn credit(&mut self, resource: Address, amount: u128) -> Result<(), ModeError> {
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
    pub fn debit(&mut self, resource: Address, amount: u128) -> Result<(), ModeError> {
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
    fn set(&mut self, resource: Address, total: u128) {
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
    use hyperscale_vm_effects::Address;

    use super::SupplyLedger;
    use crate::modes::ModeError;

    fn resource(byte: u8) -> Address {
        Address([byte; 16])
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
