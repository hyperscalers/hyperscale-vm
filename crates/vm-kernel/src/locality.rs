//! Which keys a shard owns, the part of a receipt it may apply, and the
//! part of a declaration it is charged for.
//!
//! A cross-shard transaction runs at every shard its effects reach, and
//! each one applies only the part it owns: the rest stays in the receipt as
//! the outbound record for the shard that does own it. Getting that wrong
//! does not fail loudly — it fabricates a balance for a cell this shard
//! holds none of, and every later reader of the overlay believes it.
//!
//! Every consumer of a receipt walks the same four maps, and each one used
//! to carry its own copy of the filter — the batch's apply pass, the
//! session's own fold, and the embedder's fold into committed state, which
//! is the copy furthest from this crate and the one that reaches real
//! state. [`StateDelta::owned`] is the single implementation they share: it
//! yields the entries this shard owns and nothing else, so the question
//! stops being whether a walk remembered to filter and becomes which walk
//! it is.

use std::sync::Arc;

use hyperscale_vm_effects::{Address, EffectSet, RoleId, SubstateKey, effect_units};

use crate::session::{Movement, StateDelta};

/// Which keys the executing shard owns.
///
/// A single-shard batch owns everything. A cross-shard participant
/// settles and judges only the keys it owns: a remote reservation is
/// held at its declared amount without judging (the owning shard
/// judges, and the wave combine carries its verdict), its settle
/// releases the hold and keeps the amount in the receipt as the
/// outbound record, and remote movements skip the local floor check.
#[derive(Clone)]
pub enum Locality {
    /// Every key is local.
    All,
    /// Local exactly where the predicate holds for a key's owner.
    Owned(Arc<dyn Fn(Address) -> bool + Send + Sync>),
}

impl Locality {
    /// Whether this shard owns keys under `owner`.
    #[must_use]
    pub fn is_local(&self, owner: Address) -> bool {
        match self {
            Self::All => true,
            Self::Owned(predicate) => predicate(owner),
        }
    }

    /// The declared footprint of the part of `declared` this shard owns.
    ///
    /// The same filter the delta walks apply, over the declaration rather
    /// than the outcome — and the reason the work a shard attests can be
    /// its own share rather than the whole transaction's. A participant is
    /// handed the transaction's full declaration and scopes it here; it is
    /// not handed a pre-partitioned slice.
    ///
    /// Nothing a price reads is lost on the way through. The filter turns
    /// on a target's owner and leaves the target itself alone, so a range
    /// is still charged the interval it named — unlike the delta walks,
    /// which yield entries rather than the claims they came from.
    ///
    /// Routing puts each effect on exactly one shard, and a footprint is a
    /// per-effect sum, so the participants' shares of one transaction add
    /// up to the whole declaration's footprint: neither double-counted nor
    /// dropped between them.
    #[must_use]
    pub fn footprint(&self, declared: &EffectSet) -> u64 {
        declared
            .iter()
            .filter(|effect| self.is_local(effect.target.owner()))
            .fold(0, |total, effect| {
                total.saturating_add(effect_units(effect))
            })
    }
}

impl std::fmt::Debug for Locality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => f.write_str("Locality::All"),
            Self::Owned(_) => f.write_str("Locality::Owned(..)"),
        }
    }
}

impl StateDelta {
    /// The part of this delta the shard owns.
    ///
    /// The whole delta travels in the receipt — it is one transaction's
    /// effects, and every shard derives the same one — but only the owning
    /// shard applies any given entry.
    #[must_use]
    pub const fn owned<'a>(&'a self, locality: &'a Locality) -> OwnedDelta<'a> {
        OwnedDelta {
            delta: self,
            locality,
        }
    }
}

/// One delta as one shard sees it: four walks, each already filtered.
pub struct OwnedDelta<'a> {
    delta: &'a StateDelta,
    locality: &'a Locality,
}

impl<'a> OwnedDelta<'a> {
    /// Owned cells changed under an exclusive write.
    pub fn cells(&self) -> impl Iterator<Item = (SubstateKey, &'a Option<Vec<u8>>)> + use<'a, '_> {
        self.delta
            .cells
            .iter()
            .filter(|(key, _)| self.locality.is_local(key.owner))
            .map(|(key, change)| (*key, change))
    }

    /// Changed entries of owned ordered collections.
    pub fn entries(
        &self,
    ) -> impl Iterator<Item = ((Address, RoleId, u128), &'a Option<Vec<u8>>)> + use<'a, '_> {
        self.delta
            .entries
            .iter()
            .filter(|((owner, ..), _)| self.locality.is_local(*owner))
            .map(|(slot, change)| (*slot, change))
    }

    /// Movements on owned amount cells. A movement on a key another shard
    /// holds folds there, never here.
    pub fn movements(&self) -> impl Iterator<Item = (SubstateKey, Movement)> + use<'a, '_> {
        self.delta
            .movements
            .iter()
            .filter(|(key, _)| self.locality.is_local(key.owner))
            .map(|(key, movement)| (*key, *movement))
    }

    /// Settlements of owned reservations. A remote reservation settles at
    /// its owning shard; the amount here is the outbound record.
    pub fn settles(&self) -> impl Iterator<Item = (SubstateKey, u128)> + use<'a, '_> {
        self.delta
            .settles
            .iter()
            .filter(|(key, _)| self.locality.is_local(key.owner))
            .map(|(key, amount)| (*key, *amount))
    }
}
