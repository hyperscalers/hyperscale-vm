//! The effect vocabulary: a declared access, and the folding set of them.
//!
//! Beside the target and mode types it is built from, so the whole of
//! "what a transaction declares" has one home. The machinery that
//! *produces* declarations — the DSL, evaluation, routing — lives in the
//! effects crate; what it produces is wire vocabulary, and it lives here.

use std::collections::{BTreeMap, BTreeSet};

use crate::address::{EffectTarget, SubstateKey};
use crate::mode::{Mode, ModeKind};

/// A declared access: target plus mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Effect {
    /// What is accessed.
    pub target: EffectTarget,
    /// How it is accessed.
    pub mode: Mode,
}

/// A declaration that contradicts itself on one cell.
///
/// Both are facts about the declaration rather than about state, which
/// is why they are refused where the set is built rather than carried to
/// the shard that would have to judge them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EffectConflict {
    /// Summing declared reserve amounts overflowed `u128`.
    #[error("declared reserve amounts overflow")]
    ReserveOverflow,
}

/// A set of declared accesses with union semantics: identical effects
/// dedup, and reserve amounts on the same target fold by summation, so the
/// set carries the transaction's total declared demand per key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectSet {
    by_target: BTreeMap<EffectTarget, BTreeSet<Mode>>,
}

impl EffectSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            by_target: BTreeMap::new(),
        }
    }

    /// Add one effect, folding what two clauses on one target mean
    /// together: reserve amounts sum, and presence requirements meet.
    ///
    /// Answers whether the set moved. A caller keeping an ordered view
    /// beside the set needs that and cannot get it from the error: the
    /// only refusal here is an overflowing reserve total, so a repeated
    /// read is `Ok` exactly as a novel one is, and asking `is_ok()` is
    /// asking a question this cannot answer.
    ///
    /// # Errors
    ///
    /// [`EffectConflict`] where the fold has no answer: a reserve total
    /// past `u128`.
    pub fn insert(&mut self, effect: Effect) -> Result<bool, EffectConflict> {
        let modes = self.by_target.entry(effect.target).or_default();
        if let Mode::Reserve { amount } = effect.mode {
            let existing = modes.iter().find_map(|mode| match mode {
                Mode::Reserve { amount } => Some(*amount),
                _ => None,
            });
            if let Some(prior) = existing {
                let total = prior
                    .checked_add(amount)
                    .ok_or(EffectConflict::ReserveOverflow)?;
                modes.remove(&Mode::Reserve { amount: prior });
                modes.insert(Mode::Reserve { amount: total });
                // The set changed even though it holds no new effect:
                // what the reserver may take rose by this one's amount.
                return Ok(true);
            }
        }
        Ok(modes.insert(effect.mode))
    }

    /// Every effect in the set, in canonical (target, mode) order.
    pub fn iter(&self) -> impl Iterator<Item = Effect> + '_ {
        self.by_target.iter().flat_map(|(target, modes)| {
            modes.iter().map(move |mode| Effect {
                target: *target,
                mode: *mode,
            })
        })
    }

    /// The number of (target, mode) pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_target.values().map(BTreeSet::len).sum()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_target.is_empty()
    }

    /// The provision requirement of this effect set: the targets whose
    /// committed values a counterpart shard must carry — fresh reads and
    /// the prior values of read-modify-writes. Deltas read nothing and
    /// reservation feasibility is judged at the owning shard, so neither
    /// provisions. A commutative-only leg therefore provisions nothing
    /// at all.
    #[must_use]
    pub fn provision_targets(&self) -> BTreeSet<EffectTarget> {
        self.by_target
            .iter()
            .filter(|(_, modes)| {
                modes
                    .iter()
                    .any(|mode| matches!(mode.kind(), ModeKind::Read | ModeKind::Write))
            })
            .map(|(target, _)| *target)
            .collect()
    }

    /// Whether the exact (target, mode) pair is present.
    #[must_use]
    pub fn contains(&self, effect: &Effect) -> bool {
        self.by_target
            .get(&effect.target)
            .is_some_and(|modes| modes.contains(&effect.mode))
    }

    /// The first point target this set claims both exclusively and
    /// commutatively, if any.
    ///
    /// The two record differently — a receipt carries absolutes for the
    /// one and movements for the other — so a set holding both on one
    /// cell has no receipt to produce. Asked of the set rather than of a
    /// clause list, because the set is where a target's modes are already
    /// gathered.
    #[must_use]
    pub fn self_conflicting(&self) -> Option<SubstateKey> {
        self.by_target.iter().find_map(|(target, modes)| {
            let EffectTarget::Point(key) = target else {
                return None;
            };
            let exclusive = modes.iter().any(|mode| mode.kind() == ModeKind::Write);
            let commutative = modes
                .iter()
                .any(|mode| matches!(mode.kind(), ModeKind::Delta | ModeKind::Reserve));
            (exclusive && commutative).then_some(*key)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Effect, EffectSet};
    use crate::address::{
        Address, AddressClass, CollectionId, EffectTarget, LocalKey, SubstateKey,
    };
    use crate::mode::{Mode, Moves};

    /// Distinct point targets, with no derivation: what these tests need
    /// of a key is only that two differ.
    fn target(byte: u8) -> EffectTarget {
        EffectTarget::Point(SubstateKey {
            owner: Address::new([0x10; 31], AddressClass::Component),
            local: LocalKey([byte; 16]),
        })
    }

    #[test]
    fn only_read_and_write_targets_provision() {
        // A counterpart shard has to carry what execution reads: fresh
        // reads, and the prior value a read-modify-write folds over.
        // Deltas read nothing and a reservation is judged where it
        // lives — so a commutative-only leg provisions nothing at all.
        let mut set = EffectSet::new();
        for (byte, mode) in [
            (1, Mode::Read),
            (2, Mode::Write { moves: Moves::Both }),
            (3, Mode::Delta),
            (4, Mode::Reserve { amount: 5 }),
        ] {
            set.insert(Effect {
                target: target(byte),
                mode,
            })
            .unwrap();
        }
        assert_eq!(
            set.provision_targets(),
            BTreeSet::from([target(1), target(2)])
        );

        // A cell carrying both a delta and a read still provisions: the
        // read is what needs the value.
        let mut mixed = EffectSet::new();
        mixed
            .insert(Effect {
                target: target(3),
                mode: Mode::Read,
            })
            .unwrap();
        mixed
            .insert(Effect {
                target: target(3),
                mode: Mode::Delta,
            })
            .unwrap();
        assert_eq!(mixed.provision_targets(), BTreeSet::from([target(3)]));

        assert!(EffectSet::new().provision_targets().is_empty());
    }

    #[test]
    fn a_self_conflict_is_an_exclusive_beside_a_commutative() {
        let cell = SubstateKey {
            owner: Address::new([1; 31], AddressClass::Component),
            local: LocalKey([2; 16]),
        };
        let set_of = |modes: &[Mode]| {
            let mut set = EffectSet::new();
            for mode in modes {
                set.insert(Effect {
                    target: EffectTarget::Point(cell),
                    mode: *mode,
                })
                .unwrap();
            }
            set
        };

        for pair in [
            [Mode::Write { moves: Moves::Both }, Mode::Delta],
            [
                Mode::Write { moves: Moves::Both },
                Mode::Reserve { amount: 1 },
            ],
        ] {
            assert_eq!(set_of(&pair).self_conflicting(), Some(cell), "{pair:?}");
        }

        // Everything else composes: the commutative modes with each
        // other, and reads with anything — a read is not an absolute, so
        // there is nothing for a movement to disagree with.
        for modes in [
            &[Mode::Delta, Mode::Reserve { amount: 1 }][..],
            &[Mode::Read, Mode::Delta],
            &[Mode::Read, Mode::Write { moves: Moves::Both }],
            &[Mode::Write { moves: Moves::Both }],
        ] {
            assert_eq!(set_of(modes).self_conflicting(), None, "{modes:?}");
        }

        // A collection target is never one: it holds no amount, so the
        // pairing the check is about cannot arise.
        let mut ranges = EffectSet::new();
        for mode in [Mode::Write { moves: Moves::Both }, Mode::Delta] {
            ranges
                .insert(Effect {
                    target: EffectTarget::Range {
                        owner: Address::new([1; 31], AddressClass::Component),
                        collection: CollectionId([3; 16]),
                        lo: 0,
                        hi: 9,
                        cap: 4,
                    },
                    mode,
                })
                .unwrap();
        }
        assert_eq!(ranges.self_conflicting(), None);
    }

    #[test]
    fn effect_set_folds_reserves_and_dedups() {
        let target = target(1);
        let mut set = EffectSet::new();
        set.insert(Effect {
            target,
            mode: Mode::Reserve { amount: 100 },
        })
        .unwrap();
        set.insert(Effect {
            target,
            mode: Mode::Reserve { amount: 50 },
        })
        .unwrap();
        set.insert(Effect {
            target,
            mode: Mode::Delta,
        })
        .unwrap();
        set.insert(Effect {
            target,
            mode: Mode::Delta,
        })
        .unwrap();
        assert_eq!(set.iter().count(), 2);
        assert!(set.contains(&Effect {
            target,
            mode: Mode::Reserve { amount: 150 },
        }));
        assert!(set.contains(&Effect {
            target,
            mode: Mode::Delta,
        }));

        let overflow = set.insert(Effect {
            target,
            mode: Mode::Reserve { amount: u128::MAX },
        });
        assert!(overflow.is_err());
    }
}
