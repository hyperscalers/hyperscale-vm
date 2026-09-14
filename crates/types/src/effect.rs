//! The effect vocabulary: a declared access, and the folding set of them.
//!
//! Beside the target and mode types it is built from, so the whole of
//! "what a transaction declares" has one home. The machinery that
//! *produces* declarations — the DSL, evaluation, routing — lives in the
//! effects crate; what it produces is wire vocabulary, and it lives here.

use std::collections::{BTreeMap, BTreeSet};

use crate::address::{EffectTarget, SubstateKey};
use crate::mode::{ConflictClass, Mode, ModeKind};
use crate::writes::MAX_SLOT_WIDTH;

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

/// What a set holds for one target: the modes declared on it, and the
/// most bytes one leaf under it may hold.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Declared {
    modes: BTreeSet<Mode>,
    /// The leaf width, folded by minimum: a target inserted without one
    /// is bounded at [`MAX_SLOT_WIDTH`], and a stated width lowers it.
    width: u32,
}

/// A set of declared accesses with union semantics: identical effects
/// dedup, and reserve amounts on the same target fold by summation, so the
/// set carries the transaction's total declared demand per key.
///
/// Beside the modes, each target carries the width of the leaves it
/// reaches, which is what bounds the bytes a declaration can read or
/// write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectSet {
    by_target: BTreeMap<EffectTarget, Declared>,
}

impl EffectSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            by_target: BTreeMap::new(),
        }
    }

    /// Add one effect at the width of the leaves its target reaches,
    /// folding what two clauses on one target mean together: reserve
    /// amounts sum, presence requirements meet, and widths take the
    /// narrower.
    ///
    /// Every insert states a width or a source, because a fold that
    /// could leave one unstated would widen its target to the cap and
    /// price every walk over it as the widest leaf there is; the two
    /// folds that once did were found by a transaction running out of
    /// gas on a page of addresses.
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
    pub fn insert_bounded(&mut self, effect: Effect, width: u32) -> Result<bool, EffectConflict> {
        let declared = self
            .by_target
            .entry(effect.target)
            .or_insert_with(|| Declared {
                modes: BTreeSet::new(),
                width: MAX_SLOT_WIDTH,
            });
        let narrowed = width < declared.width;
        declared.width = declared.width.min(width);
        let modes = &mut declared.modes;
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
        Ok(modes.insert(effect.mode) || narrowed)
    }

    /// [`insert_bounded`](Self::insert_bounded) at the width `source`
    /// holds the target at: how a set folded from another keeps what the
    /// other stated.
    ///
    /// # Errors
    ///
    /// As [`insert_bounded`](Self::insert_bounded).
    pub fn insert_from(&mut self, effect: Effect, source: &Self) -> Result<bool, EffectConflict> {
        self.insert_bounded(effect, source.width_of(&effect.target))
    }

    /// [`insert_bounded`](Self::insert_bounded) at the cap, for a target
    /// whose slot nobody can name: a cell the kernel reaches by key
    /// rather than through a declaration, or a set a test builds by
    /// hand. A declaration evaluated from a signature never lands here.
    ///
    /// # Errors
    ///
    /// As [`insert_bounded`](Self::insert_bounded).
    pub fn insert_at_cap(&mut self, effect: Effect) -> Result<bool, EffectConflict> {
        self.insert_bounded(effect, MAX_SLOT_WIDTH)
    }

    /// The most bytes one leaf under `target` may hold, or
    /// [`MAX_SLOT_WIDTH`] for a target the set does not hold.
    #[must_use]
    pub fn width_of(&self, target: &EffectTarget) -> u32 {
        self.by_target
            .get(target)
            .map_or(MAX_SLOT_WIDTH, |declared| declared.width)
    }

    /// The bytes the set lets a body read off the store: each target's
    /// [`read_bytes`] at the width the set holds for it.
    #[must_use]
    pub fn read_bytes(&self) -> u64 {
        self.by_target
            .iter()
            .fold(0u64, |total, (target, declared)| {
                total.saturating_add(read_bytes(target, declared.width))
            })
    }

    /// The bytes the set lets a body write onto one target: the widest
    /// of the modes declared on it, at the width the set holds for it.
    ///
    /// The widest and not the sum, because a leaf reached under several
    /// modes is still one leaf, written once, and its update reads one
    /// tree path. The same argument [`read_bytes`](Self::read_bytes)
    /// makes for reads — one leaf read once serves every mode declared
    /// on it — and it does not change on the other side of the store.
    ///
    /// Asked per target so a caller attributing the figure to whoever
    /// owns the leaf gets the same rule the whole-set fold uses. Two
    /// implementations of this would be two prices for one transaction,
    /// and the one a wallet is quoted is the one it signs a ceiling
    /// against.
    #[must_use]
    pub fn write_bytes_of(&self, target: &EffectTarget) -> u64 {
        self.by_target.get(target).map_or(0, |declared| {
            declared
                .modes
                .iter()
                .map(|mode| write_bytes(target, *mode, declared.width))
                .max()
                .unwrap_or(0)
        })
    }

    /// The bytes the set lets a body write onto the store:
    /// [`write_bytes_of`](Self::write_bytes_of) over every target.
    #[must_use]
    pub fn write_bytes(&self) -> u64 {
        self.by_target.keys().fold(0u64, |total, target| {
            total.saturating_add(self.write_bytes_of(target))
        })
    }

    /// The bytes the set leaves behind on one target: the widest of the
    /// modes declared on it, carrying the leaf's own width and nothing
    /// else.
    ///
    /// Not [`write_bytes_of`](Self::write_bytes_of), which carries
    /// [`WRITE_LEAF_BYTES`] beside the width because an update reads the
    /// tree path down to its leaf. Those reads are most of what a write
    /// *costs* and none of what it *keeps* — they touch nothing after the
    /// block. A dimension counting them would count a quantity nothing
    /// retains.
    #[must_use]
    pub fn retained_bytes_of(&self, target: &EffectTarget) -> u64 {
        self.by_target.get(target).map_or(0, |declared| {
            declared
                .modes
                .iter()
                .map(|mode| retained_bytes(target, *mode, declared.width))
                .max()
                .unwrap_or(0)
        })
    }

    /// The bytes the set leaves behind on the store:
    /// [`retained_bytes_of`](Self::retained_bytes_of) over every target.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.by_target.keys().fold(0u64, |total, target| {
            total.saturating_add(self.retained_bytes_of(target))
        })
    }

    /// Every effect in the set, in canonical (target, mode) order.
    pub fn iter(&self) -> impl Iterator<Item = Effect> + '_ {
        self.by_target.iter().flat_map(|(target, declared)| {
            declared.modes.iter().map(move |mode| Effect {
                target: *target,
                mode: *mode,
            })
        })
    }

    /// Every target the set names, once, in canonical order.
    ///
    /// What [`iter`](Self::iter) flattens away. A caller asking what a
    /// declaration *reaches* — which cells to fetch, which shard holds
    /// them — wants the target and not the modes on it, and taking that
    /// off the flattened view visits a target once per mode: a cell
    /// declared read and written is two asks for one leaf.
    pub fn targets(&self) -> impl Iterator<Item = EffectTarget> + '_ {
        self.by_target.keys().copied()
    }

    /// The number of (target, mode) pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_target
            .values()
            .map(|declared| declared.modes.len())
            .sum()
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
            .filter(|(_, declared)| {
                declared
                    .modes
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
            .is_some_and(|declared| declared.modes.contains(&effect.mode))
    }

    /// The first point target this set claims both exclusively and
    /// commutatively, if any.
    ///
    /// The two judge one debit at different moments: the exclusive hold
    /// performs the read-modify-write and refuses an over-take at the
    /// call, where a commutative movement queues and leaves the question
    /// to the fold. A body handed both handles onto one cell meets
    /// whichever discipline it reached for, so which refusal the
    /// transaction sees stops being a property of what it declared. A
    /// declaration names one discipline per cell.
    ///
    /// A read beside either is not one: reading a cell answers the same
    /// question through both byte handles, so there is no second
    /// discipline for it to pick between.
    ///
    /// Read off the conflict class rather than a mode list beside it, so
    /// a commutative mode named later is covered by being commutative.
    /// Asked of the set rather than of a clause list, because the set is
    /// where a target's modes are already gathered.
    #[must_use]
    pub fn self_conflicting(&self) -> Option<SubstateKey> {
        self.by_target.iter().find_map(|(target, declared)| {
            let EffectTarget::Point(key) = target else {
                return None;
            };
            let claims = |class| {
                declared
                    .modes
                    .iter()
                    .any(|mode| mode.kind().conflict_class() == class)
            };
            (claims(ConflictClass::Write) && claims(ConflictClass::Movement)).then_some(*key)
        })
    }
}

/// The leaves `target` reaches: one for a point or an entry, and for a
/// range its cap plus the coverage probe and presence seek every scan
/// makes before the first entry comes back.
#[must_use]
const fn leaves_read(target: &EffectTarget) -> u64 {
    match target {
        EffectTarget::Point(_) | EffectTarget::Entry { .. } => 1,
        EffectTarget::Range { cap, .. } => (*cap as u64).saturating_add(1),
    }
}

/// The leaves `target` lets a body write: one for a point or an entry,
/// and for a range its cap.
#[must_use]
const fn leaves_written(target: &EffectTarget) -> u64 {
    match target {
        EffectTarget::Point(_) | EffectTarget::Entry { .. } => 1,
        EffectTarget::Range { cap, .. } => *cap as u64,
    }
}

/// The bytes an entry leaf carries beside the value it holds: the
/// collection and the order it commits under, and their framing.
///
/// An entry commits under a digest of its owner, collection and order,
/// and the leaf carries the last two so the ordered index is derivable
/// from the leaves alone. So a leaf is never its value alone, and a
/// collection whose values are empty is not a collection that is free to
/// walk — `width` is what a slot's *value* may hold and says nothing
/// about the leaf around it.
///
/// An upper bound rather than the figure: the value's own length rides
/// in front of it as a varint, so the framing is 33 bytes up to a
/// 127-byte value, 34 up to 16,383 and 35 at
/// [`MAX_SLOT_WIDTH`](crate::writes::MAX_SLOT_WIDTH). The widest, since
/// a dimension that priced the narrowest would underprice every leaf
/// above it. Pinned against the encoder by the outer's
/// `an_entry_leaf_costs_what_the_dimension_prices_it`.
pub const ENTRY_LEAF_BYTES: u64 = 35;

/// The bytes one leaf under `target` holds: its value at `width`, and
/// for an entry the collection and order it commits under.
///
/// The one place the shape of a leaf is stated, so the dimension that
/// prices reading one, the dimension that prices keeping one, and the
/// dimension that prices writing one cannot disagree about what one is.
#[must_use]
pub const fn leaf_bytes(target: &EffectTarget, width: u32) -> u64 {
    match target {
        EffectTarget::Point(_) => width as u64,
        EffectTarget::Entry { .. } | EffectTarget::Range { .. } => entry_leaf_bytes(width),
    }
}

/// The bytes one entry leaf holds: its value at `width`, and the
/// collection and order it commits under.
///
/// Split out of [`leaf_bytes`] for the caller that holds a width and no
/// target — the kernel's walk floor, pricing an interval it has already
/// resolved — so the fuel a scan costs and the bytes it reads are one
/// shape rather than two.
#[must_use]
pub const fn entry_leaf_bytes(width: u32) -> u64 {
    ENTRY_LEAF_BYTES.saturating_add(width as u64)
}

/// The bytes one declared target lets a body read off the store, at
/// `width` per leaf.
///
/// Every mode reads: a write hands the body the leaf it overwrites, and
/// a commutative movement reads the amount cell it moves. The scan floor
/// charges the same figure in fuel at the boundary rate; this is the
/// disk's dimension, not a second charge for the copy.
#[must_use]
pub const fn read_bytes(target: &EffectTarget, width: u32) -> u64 {
    leaves_read(target).saturating_mul(leaf_bytes(target, width))
}

/// What one written leaf costs before any of its bytes, in the byte
/// terms the write dimension is denominated in.
///
/// A leaf write is not proportional to what it carries. The update
/// reads the tree path down to the leaf, and those reads are most of
/// what a write costs — measured, the tree hashing is a tenth of it and
/// the value bytes barely register: sixty-four times the width costs
/// 1.2 times the time. Without a floor, two transactions writing the
/// same byte total differ by that factor in real cost and price alike,
/// and a block's cap counts a quantity nothing spends.
///
/// The read side has said this since [`crate::writes::MAX_SLOT_WIDTH`]'s
/// own plan: a seek walks the layers whether or not the interval holds
/// anything, so an empty page is not free. This is the same statement
/// on the other side of the store.
///
/// The figure is the per-leaf cost at the marginal byte rate, and like
/// every weight it is a placeholder — the measurement brackets it
/// between roughly 700 and 7,000 bytes depending on how much of the
/// tree stays cached, and this is the middle of that. What it replaces
/// is zero, which is the one value it is certainly not.
pub const WRITE_LEAF_BYTES: u64 = 2_048;

/// What writing one leaf holding `leaf` bytes costs, in the byte terms
/// the write dimension is denominated in: the leaf's own bytes over
/// [`WRITE_LEAF_BYTES`].
///
/// The one place the write dimension states what a leaf costs, so a
/// caller pricing a leaf the kernel does not declare — a crossing
/// record, a claim, the cell a shard writes to say it committed —
/// reaches the same figure as the declaration does for a leaf it holds.
/// Stated apart from [`write_bytes`] because those cells have no
/// [`EffectTarget`] and no [`Mode`]: they are leaves the chain writes,
/// not accesses a body declared.
#[must_use]
pub const fn written_leaf(leaf: u64) -> u64 {
    WRITE_LEAF_BYTES.saturating_add(leaf)
}

/// The bytes one declared effect lets a body write onto the store:
/// nothing for a read, and for every mode that moves or overwrites, each
/// leaf it reaches at [`written_leaf`].
#[must_use]
pub const fn write_bytes(target: &EffectTarget, mode: Mode, width: u32) -> u64 {
    match mode {
        Mode::Read => 0,
        Mode::Delta { .. } | Mode::Reserve { .. } | Mode::Write { .. } => {
            leaves_written(target).saturating_mul(written_leaf(leaf_bytes(target, width)))
        }
    }
}

/// The bytes one declared effect leaves on the store: nothing for a
/// read, and for every mode that moves or overwrites, each written leaf
/// at its own `width`.
///
/// [`write_bytes`]'s quantity without [`WRITE_LEAF_BYTES`]: what lands
/// and stays, rather than what putting it there costs.
#[must_use]
pub const fn retained_bytes(target: &EffectTarget, mode: Mode, width: u32) -> u64 {
    match mode {
        Mode::Read => 0,
        Mode::Delta { .. } | Mode::Reserve { .. } | Mode::Write { .. } => {
            leaves_written(target).saturating_mul(leaf_bytes(target, width))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{ENTRY_LEAF_BYTES, Effect, EffectSet, WRITE_LEAF_BYTES, read_bytes};
    use crate::address::{
        Address, AddressClass, CollectionId, EffectTarget, LocalKey, SubstateKey,
    };
    use crate::mode::{ConflictClass, Mode, ModeKind, Moves};
    use crate::writes::MAX_SLOT_WIDTH;

    /// Distinct point targets, with no derivation: what these tests need
    /// of a key is only that two differ.
    fn target(byte: u8) -> EffectTarget {
        EffectTarget::Point(SubstateKey {
            owner: Address::new([0x10; 31], AddressClass::Component),
            local: LocalKey([byte; 16]),
        })
    }

    /// One target reached under several modes is one target. The
    /// flattened view names it once per mode, which is the right reading
    /// for a price and the wrong one for a fetch.
    #[test]
    fn a_target_is_named_once_however_many_modes_reach_it() {
        let mut set = EffectSet::new();
        for mode in [
            Mode::Read,
            Mode::Reserve { amount: 7 },
            Mode::Write { moves: Moves::Out },
        ] {
            set.insert_bounded(
                Effect {
                    target: target(1),
                    mode,
                },
                40,
            )
            .unwrap();
        }
        set.insert_bounded(
            Effect {
                target: target(2),
                mode: Mode::Read,
            },
            40,
        )
        .unwrap();

        assert_eq!(set.iter().count(), 4, "four (target, mode) pairs");
        assert_eq!(
            set.targets().collect::<Vec<_>>(),
            vec![target(1), target(2)],
            "but two targets, in canonical order"
        );
    }

    /// A leaf written under several modes is one leaf written.
    ///
    /// The figure a caller attributing bytes to an owner reads must be
    /// the one the whole-set fold uses, or a wallet is quoted a price
    /// the chain does not charge and signs a ceiling under it.
    #[test]
    fn a_target_written_under_two_modes_is_written_once() {
        let mut set = EffectSet::new();
        for mode in [
            Mode::Reserve { amount: 100 },
            Mode::Delta { moves: Moves::In },
        ] {
            set.insert_bounded(
                Effect {
                    target: target(1),
                    mode,
                },
                16,
            )
            .unwrap();
        }

        let once = set.write_bytes_of(&target(1));
        assert_eq!(
            once,
            WRITE_LEAF_BYTES + 16,
            "one leaf at the floor and its own width, whatever reaches it"
        );
        assert_eq!(
            set.write_bytes(),
            once,
            "and the whole-set fold is the per-target figure, not a sum over modes"
        );
        assert_eq!(
            set.write_bytes_of(&target(2)),
            0,
            "a target the set does not hold is written not at all"
        );
    }

    /// A collection whose values are empty is not free to walk.
    ///
    /// `width` bounds a slot's *value*; the leaf around it carries the
    /// collection and order the entry commits under. A protocol slot
    /// holding presence alone — an nf-vault — states a width of zero, and
    /// reading a page of one is real work against a real tree.
    #[test]
    fn an_entry_leaf_is_never_its_value_alone() {
        let range = EffectTarget::Range {
            owner: Address::new([0x10; 31], AddressClass::Component),
            collection: CollectionId([0xEE; 16]),
            lo: 0,
            hi: u128::MAX,
            cap: 1_000,
        };
        assert_eq!(
            read_bytes(&range, 0),
            1_001 * ENTRY_LEAF_BYTES,
            "a page of presence-only entries is priced by its leaves"
        );
        assert_eq!(
            read_bytes(&range, 16),
            1_001 * (ENTRY_LEAF_BYTES + 16),
            "and a valued one by the leaf around the value too"
        );

        // A point cell is its value: there is no collection or order
        // committed beside it, so there is nothing to add.
        assert_eq!(read_bytes(&target(1), 16), 16);
    }

    /// A target's width is what it was stated at, folded by minimum: a
    /// plain insert leaves a stated width alone, a fold from another set
    /// carries the other's statement, and a fresh set knows nothing but
    /// the cap.
    #[test]
    fn a_width_folds_by_minimum_and_rides_a_fold_from_its_source() {
        let read = Effect {
            target: target(1),
            mode: Mode::Read,
        };
        let mut set = EffectSet::new();
        assert_eq!(set.width_of(&read.target), MAX_SLOT_WIDTH);
        set.insert_bounded(read, 40).unwrap();
        set.insert_at_cap(read).unwrap();
        assert_eq!(set.width_of(&read.target), 40);
        assert!(
            set.insert_bounded(read, 8).unwrap(),
            "a narrower width moves the set"
        );
        assert_eq!(set.width_of(&read.target), 8);

        let mut folded = EffectSet::new();
        folded.insert_from(read, &set).unwrap();
        assert_eq!(folded.width_of(&read.target), 8);
        assert_eq!(folded, set);
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
            (3, Mode::Delta { moves: Moves::Both }),
            (4, Mode::Reserve { amount: 5 }),
        ] {
            set.insert_at_cap(Effect {
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
            .insert_at_cap(Effect {
                target: target(3),
                mode: Mode::Read,
            })
            .unwrap();
        mixed
            .insert_at_cap(Effect {
                target: target(3),
                mode: Mode::Delta { moves: Moves::Both },
            })
            .unwrap();
        assert_eq!(mixed.provision_targets(), BTreeSet::from([target(3)]));

        assert!(EffectSet::new().provision_targets().is_empty());
    }

    /// A mode standing for each kind. Total over [`ModeKind`], so a kind
    /// added later has to choose its parameters here.
    const fn mode_of(kind: ModeKind) -> Mode {
        match kind {
            ModeKind::Read => Mode::Read,
            ModeKind::Delta => Mode::Delta { moves: Moves::Both },
            ModeKind::Reserve => Mode::Reserve { amount: 1 },
            ModeKind::Write => Mode::Write { moves: Moves::Both },
        }
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
                set.insert_at_cap(Effect {
                    target: EffectTarget::Point(cell),
                    mode: *mode,
                })
                .unwrap();
            }
            set
        };

        // Every ordered pairing, so the answer is stated for each rather
        // than for whichever ones a case happened to list. Exclusive
        // beside commutative is the one that conflicts, both ways round;
        // the commutative modes compose with each other, and a read
        // composes with anything — reading a cell answers the same
        // question through either byte handle.
        for left in ModeKind::ALL {
            for right in ModeKind::ALL {
                let classes = [left.conflict_class(), right.conflict_class()];
                let split = classes.contains(&ConflictClass::Write)
                    && classes.contains(&ConflictClass::Movement);
                let pair = [mode_of(left), mode_of(right)];
                assert_eq!(
                    set_of(&pair).self_conflicting(),
                    split.then_some(cell),
                    "{left:?} beside {right:?}",
                );
            }
        }

        // A collection target is never one: it holds no amount, so the
        // pairing the check is about cannot arise.
        let mut ranges = EffectSet::new();
        for mode in [
            Mode::Write { moves: Moves::Both },
            Mode::Delta { moves: Moves::Both },
        ] {
            ranges
                .insert_at_cap(Effect {
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
        set.insert_at_cap(Effect {
            target,
            mode: Mode::Reserve { amount: 100 },
        })
        .unwrap();
        set.insert_at_cap(Effect {
            target,
            mode: Mode::Reserve { amount: 50 },
        })
        .unwrap();
        set.insert_at_cap(Effect {
            target,
            mode: Mode::Delta { moves: Moves::Both },
        })
        .unwrap();
        set.insert_at_cap(Effect {
            target,
            mode: Mode::Delta { moves: Moves::Both },
        })
        .unwrap();
        assert_eq!(set.iter().count(), 2);
        assert!(set.contains(&Effect {
            target,
            mode: Mode::Reserve { amount: 150 },
        }));
        assert!(set.contains(&Effect {
            target,
            mode: Mode::Delta { moves: Moves::Both },
        }));

        let overflow = set.insert_at_cap(Effect {
            target,
            mode: Mode::Reserve { amount: u128::MAX },
        });
        assert!(overflow.is_err());
    }

    /// The byte terms follow the declaration: a range reads its cap plus
    /// the probe and writes its cap, a point reads and writes one leaf,
    /// and a read writes nothing.
    #[test]
    fn declared_bytes_follow_the_cap_and_the_width() {
        let range = EffectTarget::Range {
            owner: Address::new([1; 31], AddressClass::Component),
            collection: CollectionId([2; 16]),
            lo: 0,
            hi: 100,
            cap: 7,
        };
        assert_eq!(read_bytes(&range, 16), 8 * (ENTRY_LEAF_BYTES + 16));
        assert_eq!(super::write_bytes(&range, Mode::Read, 16), 0);
        // A read's leaves are the cap and its probe, at the leaf each —
        // which for an entry is the collection and order it commits
        // under, around the value. A write's are the cap alone, and each
        // carries the per-leaf floor before the leaf's own bytes: the
        // path reads the update pays for whatever the leaf holds.
        assert_eq!(
            super::write_bytes(&range, Mode::Write { moves: Moves::Both }, 16),
            7 * (WRITE_LEAF_BYTES + ENTRY_LEAF_BYTES + 16)
        );
        assert_eq!(read_bytes(&target(1), 4096), 4096);
        assert_eq!(
            super::write_bytes(&target(1), Mode::Delta { moves: Moves::Both }, 16),
            WRITE_LEAF_BYTES + 16
        );

        let mut set = EffectSet::new();
        set.insert_bounded(
            Effect {
                target: range,
                mode: Mode::Read,
            },
            16,
        )
        .unwrap();
        set.insert_bounded(
            Effect {
                target: target(1),
                mode: Mode::Write { moves: Moves::Both },
            },
            4096,
        )
        .unwrap();
        assert_eq!(set.read_bytes(), 8 * (ENTRY_LEAF_BYTES + 16) + 4096);
        assert_eq!(set.write_bytes(), WRITE_LEAF_BYTES + 4096);
        // A target the set holds at no declared width is priced at the
        // cap, like everything else about it.
        let mut capped = EffectSet::new();
        capped
            .insert_at_cap(Effect {
                target: target(2),
                mode: Mode::Read,
            })
            .unwrap();
        assert_eq!(capped.read_bytes(), u64::from(MAX_SLOT_WIDTH));
    }
}
