//! What a transaction did to supply: the two operations that move it.
//!
//! Supply is not a cell. No key holds it, and what changes it is the
//! authority a grant conferred rather than any write — so what a receipt
//! records is the pair of totals its transaction moved, and chain-wide
//! supply is a fold over receipts rather than a number anybody keeps.
//!
//! No accumulator stands behind it, and that is a decision. A sum does
//! not live at a prefix: maintaining one across a split costs a re-fold
//! over every cell the child inherits, and the result is unverifiable
//! anyway, since two children's totals adding to their parent's pins
//! nothing about which resource went to which side. What replaces it is
//! the conservation fold in
//! [`finish`](crate::KernelSession::finish), which judges each execution
//! whole: a mint is a loss and a burn is a gain, so value entering the
//! world has to land somewhere and value leaving it has to have come
//! from somewhere.
//!
//! Two operations move it, and both carry a resource address because a
//! grant does: minting brings value into existence under the authority
//! over one resource, and burning takes it out under the same. An
//! aborting transaction records neither, on the same terms its events do
//! not survive.
//!
//! Nothing else moves it, and nothing else needs to. A transfer is a
//! debit and a credit on two cells holding the same resource, which sums
//! to zero however many cells it crosses. Value crossing a shard
//! boundary moves no supply either — it exists on both sides of the
//! crossing — which is why an escrow is its own term in that fold and
//! not a term here.

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
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::ResourceAddr;

    use super::SupplyDelta;

    const fn resource(byte: u8) -> ResourceAddr {
        ResourceAddr::new([byte; 31])
    }

    /// A resource minted and burned in one transaction is one resource.
    ///
    /// It sits in both maps, and a caller folding per resource would
    /// count each of its halves twice if the two key sets were chained
    /// rather than merged — which is how the conservation fold read a
    /// mint-and-burn as a transaction that gained and lost double.
    #[test]
    fn a_resource_moved_both_ways_is_named_once() {
        let unit = resource(0xA1);
        let mut delta = SupplyDelta::default();
        delta.mint(unit, 500).expect("within bounds");
        delta.burn(unit, 300).expect("within bounds");

        assert_eq!(delta.resources().collect::<Vec<_>>(), vec![unit]);
    }
}
