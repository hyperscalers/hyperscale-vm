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
    /// Two writes on one cell requiring opposite presences: one wants the
    /// leaf absent and the other wants it there, so their fold is a
    /// requirement nothing can satisfy.
    #[error("two writes on one cell require opposite presences")]
    Presence,
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
    /// # Errors
    ///
    /// [`EffectConflict`] where the fold has no answer — a reserve total
    /// past `u128`, or two writes requiring opposite presences.
    pub fn insert(&mut self, effect: Effect) -> Result<(), EffectConflict> {
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
                return Ok(());
            }
        }
        // Two writes on one cell are one write, and what it requires is
        // what both require — [`Presence::meet`], the same lattice the
        // publish check folds target expressions over.
        if let Mode::Write { requires } = effect.mode {
            let prior = modes.iter().find_map(|mode| match mode {
                Mode::Write { requires } => Some(*requires),
                _ => None,
            });
            if let Some(prior) = prior {
                let met = prior.meet(requires).ok_or(EffectConflict::Presence)?;
                modes.remove(&Mode::Write { requires: prior });
                modes.insert(Mode::Write { requires: met });
                return Ok(());
            }
        }
        modes.insert(effect.mode);
        Ok(())
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
    /// the prior values of read-modify-writes. Locked reads are
    /// client-proven, deltas read nothing, and reservation feasibility is
    /// judged at the owning shard, so none of them provision. A
    /// commutative-only leg therefore provisions nothing at all.
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
