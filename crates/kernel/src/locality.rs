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

use hyperscale_vm_effects::{
    Address, CollectionId, EffectSet, StateWrites, SubstateKey, effect_units,
};

use crate::session::{Movement, StateDelta};

/// Which keys the executing shard owns.
///
/// A single-shard batch owns everything. A cross-shard participant
/// settles and judges only the keys it owns: a remote reservation is
/// held at its declared amount without judging (the owning shard
/// judges, and the tick combine carries its verdict), its settle
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
    pub fn is_local(&self, owner: impl Into<Address>) -> bool {
        match self {
            Self::All => true,
            Self::Owned(predicate) => predicate(owner.into()),
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

    /// The owned part of this delta in the form a receipt carries it:
    /// exclusive writes as the absolutes they are, commutative accesses
    /// as the movements they are.
    ///
    /// Nothing is folded, because folding needs a prior value and the
    /// prior value is not known here. A receipt outlives the baseline it
    /// executed against — it is settled later, possibly after a sibling
    /// the baseline excluded — so the value a movement produces is a
    /// question for the moment it applies. [`StateWrites::resolve`] is
    /// where it gets answered.
    ///
    /// A settled reservation is a debit like any other. The distinction
    /// the delta draws between the two is about what authorized the
    /// change, and that question is closed by the time a receipt exists.
    ///
    /// # Panics
    ///
    /// Panics on an ordered-collection entry, which has no cell form.
    #[must_use]
    pub fn project(&self, locality: &Locality) -> StateWrites {
        assert!(
            self.entries.is_empty(),
            "an ordered-collection entry has no cell form"
        );
        let owned = self.owned(locality);
        let mut writes = StateWrites::default();
        for (key, change) in owned.cells() {
            writes.cells.insert(key, change.clone());
        }
        for (key, movement) in owned.movements() {
            let entry = writes.movements.entry(key).or_default();
            *entry = entry.then(movement);
        }
        for (key, settled) in owned.settles() {
            let entry = writes.movements.entry(key).or_default();
            *entry = entry.then(Movement {
                credit: 0,
                debit: settled,
            });
        }
        writes
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
    ) -> impl Iterator<Item = ((Address, CollectionId, u128), &'a Option<Vec<u8>>)> + use<'a, '_>
    {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use hyperscale_vm_effects::{Address, AddressClass, Hash32, LocalKey, SubstateKey, TxHash};

    use super::Locality;
    use crate::modes::{decode_amount, encode_amount};
    use crate::overlay::OverlayStore;
    use crate::session::{Movement, StateDelta};
    use crate::store::{MemoryStore, WorkingStore};

    fn key(owner: u8, local: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            local: LocalKey([local; 16]),
        }
    }

    /// The differential guard on project-then-resolve: the overlay
    /// applying the same operations, collapsed to plain cells, is the
    /// authority the resolved writes must reproduce key for key.
    #[test]
    fn a_resolved_projection_matches_the_overlay_application() {
        let vault = key(1, 1); // 100, movement +30 −10 → 120
        let drained = key(1, 2); // 40, movement −40 → absent
        let fresh = key(1, 3); // absent, movement +5 → 5
        let reserved = key(1, 4); // 100, settle 40 → 60
        let emptied = key(1, 5); // 25, settle 25 → absent
        let written = key(1, 6); // exclusive write
        let removed = key(1, 7); // exclusive removal
        let tx = TxHash(Hash32([9; 32]));

        let mut base = MemoryStore::new();
        base.cells.insert(vault, encode_amount(100).to_vec());
        base.cells.insert(drained, encode_amount(40).to_vec());
        base.cells.insert(reserved, encode_amount(100).to_vec());
        base.cells.insert(emptied, encode_amount(25).to_vec());
        base.cells.insert(removed, vec![1, 2, 3]);

        let mut delta = StateDelta::default();
        delta.cells.insert(written, Some(vec![7]));
        delta.cells.insert(removed, None);
        let movements = [
            (
                vault,
                Movement {
                    credit: 30,
                    debit: 10,
                },
            ),
            (
                drained,
                Movement {
                    credit: 0,
                    debit: 40,
                },
            ),
            (
                fresh,
                Movement {
                    credit: 5,
                    debit: 0,
                },
            ),
        ];
        for (cell, movement) in movements {
            delta.movements.insert(cell, movement);
        }
        delta.settles.insert(reserved, 40);
        delta.settles.insert(emptied, 25);

        let mut overlay = OverlayStore::new(Arc::new(base.clone()));
        overlay.write(written, vec![7]).unwrap();
        overlay.remove(removed).unwrap();
        for (cell, movement) in movements {
            overlay
                .apply_movement(cell, movement.credit, movement.debit)
                .unwrap();
        }
        for (cell, amount) in [(reserved, 40), (emptied, 25)] {
            overlay.hold_unjudged(cell, tx, amount);
            overlay.settle(cell, tx).unwrap();
        }
        let expected = overlay.collapse_onto(base.clone());

        let writes = delta
            .project(&Locality::All)
            .resolve(&mut |cell| base.cells.get(&cell).cloned());
        let mut folded: BTreeMap<_, _> = base.cells.clone();
        for (cell, change) in writes.cells() {
            match change {
                Some(value) => {
                    folded.insert(*cell, value.clone());
                }
                None => {
                    folded.remove(cell);
                }
            }
        }
        assert_eq!(folded, expected.cells);
        // The drains flatten to removals, not to encoded zeros.
        assert_eq!(writes.cells()[&drained], None);
        assert_eq!(writes.cells()[&emptied], None);
    }

    /// A projected receipt does not depend on the baseline it executed
    /// against — which is the point of projecting rather than flattening.
    /// The same projection resolves correctly against whatever state it
    /// eventually lands on, so a sibling that settles first is composed
    /// with rather than overwritten.
    #[test]
    fn a_projection_resolves_against_whatever_it_lands_on() {
        let vault = key(2, 1);
        let mut delta = StateDelta::default();
        delta.movements.insert(
            vault,
            Movement {
                credit: 0,
                debit: 30,
            },
        );
        let projected = delta.project(&Locality::All);
        assert!(
            projected.cells.is_empty(),
            "a movement is not an absolute yet"
        );

        // The same receipt, landing on two different priors, debits both.
        for (before, after) in [(100u128, 70u128), (60, 30)] {
            let resolved = projected.resolve(&mut |_| Some(encode_amount(before).to_vec()));
            assert_eq!(
                decode_amount(resolved.cells()[&vault].as_ref().unwrap()).unwrap(),
                after,
            );
        }
    }

    /// A movement folds over this receipt's own exclusive write before it
    /// consults committed state.
    #[test]
    fn a_movement_folds_over_the_receipts_own_write() {
        let cell = key(1, 1);
        let mut delta = StateDelta::default();
        delta.cells.insert(cell, Some(encode_amount(50).to_vec()));
        delta.movements.insert(
            cell,
            Movement {
                credit: 0,
                debit: 20,
            },
        );
        let writes = delta
            .project(&Locality::All)
            .resolve(&mut |_| panic!("the receipt's own write answers this read"));
        assert_eq!(writes.cells()[&cell], Some(encode_amount(30).to_vec()));
    }

    /// Remote keys stay in the receipt as the outbound record; the
    /// projected writes carry owned keys only.
    #[test]
    fn a_projection_carries_owned_keys_only() {
        let local = key(1, 1);
        let remote = key(2, 1);
        let mut delta = StateDelta::default();
        for cell in [local, remote] {
            delta.movements.insert(
                cell,
                Movement {
                    credit: 5,
                    debit: 0,
                },
            );
        }
        let locality = Locality::Owned(Arc::new(|owner: Address| {
            owner == Address::new([1; 31], AddressClass::Component)
        }));
        let writes = delta.project(&locality).resolve(&mut |_| None);
        assert_eq!(writes.cells().len(), 1);
        assert_eq!(writes.cells()[&local], Some(encode_amount(5).to_vec()));
    }
}
