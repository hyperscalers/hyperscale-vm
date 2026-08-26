//! The declared footprint: what a declaration claims, in units a fee
//! schedule can price.
//!
//! Three axes. The **span** is how much key space a target names — one
//! leaf for a point or an entry, and for a range the order-key magnitude
//! of its interval. The **weight** is how much of the mode lattice the
//! claim excludes, counted off [`compatible`] itself rather than
//! tabulated beside it, so a change to the lattice moves the price with
//! it instead of leaving a table to drift. The **depth** is how much
//! execution the claim buys: the entries a body may walk through it.
//!
//! Span and weight multiply; depth adds. The first two together price
//! *exclusion* — what a declaration stops others doing, a property of
//! the interval whatever it holds — and depth prices *work*, a property
//! of what the body walks. A claim that excludes the whole order-key
//! space and reads one entry is expensive on one axis and cheap on the
//! other, and both are true.
//!
//! Span is the axis a per-effect price misses, and missing it is not
//! neutral: conflict on a collection is interval overlap
//! (`vm-kernel`'s `targets_overlap`), so an interval spanning the whole
//! order-key space excludes every other declaration on that collection
//! while costing exactly what a single-entry interval costs. Charging the
//! span is what stops one effect buying that. Depth is the axis span
//! misses in turn: a narrow interval with a large cap excludes almost
//! nothing and scans as far as its cap allows, so the cap is charged as
//! the work it buys.
//!
//! Nothing here reads state, so a footprint is computable wherever
//! [`crate::route`]'s output is — which is what lets the fee payer's shard
//! price a declaration over keys another shard owns, without asking it.
//!
//! The unit weights are structure, not calibration: the constants below
//! carry placeholder values, and what one unit costs in fee terms is set
//! against measured baselines rather than chosen here.

use hyperscale_vm_types::{Effect, EffectSet, EffectTarget, ModeKind, compatible};

/// Units charged for naming one target at all, before any span.
///
/// A declaration costs something even when it excludes nothing: it is a
/// routing entry.
pub const TARGET_UNITS: u64 = 1;

/// Units charged per order-key bit of a range's span.
///
/// Named for the axis the module doc names, which is the point: the
/// footprint's three axes are span, weight and depth, and "width" is a
/// byte count everywhere else in the vocabulary.
pub const SPAN_UNITS: u64 = 1;

/// Units charged per entry a declaration lets execution touch.
pub const DEPTH_UNITS: u64 = 1;

/// The entries-worth of work one interval seek costs before any entry
/// comes back — the declared floor of a scan.
///
/// The seek walks both overlay layers and the base whether or not the
/// interval holds anything, so a page is not free because it is empty.
/// The fuel schedule states the same floor in boundary bytes:
/// `vm-kernel`'s `SCAN_SEEK_BYTES` is this figure at the per-entry byte
/// floor, so the two schedules price one seek from one constant rather
/// than agreeing by inspection.
pub const SCAN_SEEK_ENTRIES: usize = 4;

/// The weight a mode that excluded nothing would carry — the floor every
/// mode weight is measured up from.
pub const EXCLUSIVITY_FLOOR: u64 = 1;

/// How much of the lattice `kind` excludes, as a multiplier on span.
///
/// Counted from [`compatible`], so the ordering is the lattice's rather
/// than a judgement: `delta` and `reserve` exclude fresh reads and
/// writes; `read` excludes both commutative modes as well; `write`
/// excludes everything, itself included.
///
/// The placement of `read` above the commutative modes is the part worth
/// stating out loud, because intuition puts reads near the bottom. Two
/// deltas on one amount cell coexist; a single fresh read on that cell
/// conflicts with both. Pricing `read` below `reserve` would make the
/// cheapest declaration on a hot cell the one that serializes the most
/// traffic across it.
#[must_use]
const fn mode_weight(kind: ModeKind) -> u64 {
    let kinds = ModeKind::ALL;
    let mut excluded = 0;
    let mut index = 0;
    while index < kinds.len() {
        if !compatible(kind, kinds[index]) {
            excluded += 1;
        }
        index += 1;
    }
    EXCLUSIVITY_FLOOR + excluded
}

/// The order-key bits a range's interval spans: `0` for an empty or
/// single-key interval, `128` for the whole space.
///
/// Orders of magnitude rather than keys. An order-key space is `u128` and
/// what occupies any interval of it is state, which a footprint may not
/// read — so an arithmetic width would be both unusable (a realistic
/// interval is a vanishing fraction of `u128`) and misleading (a dense
/// book occupying a narrow interval is fully excluded by a declaration
/// that width calls negligible). The magnitude claimed is the measure
/// that stays monotone and finite across both.
#[must_use]
const fn order_bits(lo: u128, hi: u128) -> u64 {
    // An inverted interval names nothing; `hi` is inclusive, so an
    // interval and its span differ by one key.
    match hi.checked_sub(lo) {
        None | Some(0) => 0,
        Some(span) => span.ilog2() as u64 + 1,
    }
}

/// The key space `target` claims, before its mode weighs it.
#[must_use]
const fn span_units(target: &EffectTarget) -> u64 {
    match target {
        EffectTarget::Point(_) | EffectTarget::Entry { .. } => TARGET_UNITS,
        EffectTarget::Range { lo, hi, .. } => {
            TARGET_UNITS.saturating_add(SPAN_UNITS.saturating_mul(order_bits(*lo, *hi)))
        }
    }
}

/// The execution work `target` lets a body walk: one entry for a point
/// or an entry access, and for a range the seek floor plus the cap's
/// worth of entries.
///
/// Charged whatever the mode: a read walks the same page a write does,
/// and how much of the lattice the claim excludes is the other axes'
/// business.
#[must_use]
const fn depth_units(target: &EffectTarget) -> u64 {
    match target {
        EffectTarget::Point(_) | EffectTarget::Entry { .. } => DEPTH_UNITS,
        EffectTarget::Range { cap, .. } => {
            DEPTH_UNITS.saturating_mul((SCAN_SEEK_ENTRIES as u64).saturating_add(*cap as u64))
        }
    }
}

/// One effect's footprint: the key space it claims weighted by how much
/// of the lattice the claim excludes, plus the depth its execution may
/// walk.
#[must_use]
pub const fn effect_units(effect: Effect) -> u64 {
    span_units(&effect.target)
        .saturating_mul(mode_weight(effect.mode.kind()))
        .saturating_add(depth_units(&effect.target))
}

/// A declaration's total footprint.
///
/// Summed per effect rather than over each collection's union, which
/// prices a fragmented declaration slightly above one interval covering
/// it. That premium is deliberate coarseness, not an incentive: precision
/// pays for itself in conflicts avoided, which is a scheduling saving far
/// larger than the difference here, and a union measure would let one
/// covering interval hide behind the precision of the ranges it swallows.
///
/// Saturating throughout, so the quantity is total for any set under any
/// calibration. Routing's own bounds ([`crate::MAX_EFFECTS_PER_SIGNATURE`],
/// [`crate::MAX_MANIFEST_NODES`]) keep an admitted declaration orders of
/// magnitude below the saturation point at the weights above — but those
/// weights are placeholders, and a price that wrapped when they moved
/// would be a fee schedule with a discount at the top.
#[must_use]
pub fn footprint(declared: &EffectSet) -> u64 {
    declared.iter().fold(0, |total, effect| {
        total.saturating_add(effect_units(effect))
    })
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{
        Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, LocalKey, Mode,
        ModeKind, Moves, SubstateKey, compatible,
    };

    use super::{
        DEPTH_UNITS, EXCLUSIVITY_FLOOR, SCAN_SEEK_ENTRIES, depth_units, effect_units, footprint,
        mode_weight, order_bits, span_units,
    };

    /// The mode kinds `kind` cannot share a key with.
    fn excluded(kind: ModeKind) -> Vec<ModeKind> {
        ModeKind::ALL
            .into_iter()
            .filter(|other| !compatible(kind, *other))
            .collect()
    }

    #[test]
    fn weight_respects_the_exclusion_ordering() {
        for narrow in ModeKind::ALL {
            for wide in ModeKind::ALL {
                let (narrow_set, wide_set) = (excluded(narrow), excluded(wide));
                if !narrow_set.iter().all(|kind| wide_set.contains(kind)) {
                    continue;
                }
                assert!(
                    mode_weight(narrow) <= mode_weight(wide),
                    "{narrow:?} excludes a subset of {wide:?} but weighs more",
                );
                if wide_set.len() > narrow_set.len() {
                    assert!(
                        mode_weight(narrow) < mode_weight(wide),
                        "{wide:?} excludes strictly more than {narrow:?} but weighs no more",
                    );
                }
            }
        }
    }

    const OWNER: Address = Address::new([7; 31], AddressClass::Component);

    fn point(byte: u8) -> EffectTarget {
        EffectTarget::Point(SubstateKey {
            owner: OWNER,
            local: LocalKey([byte; 16]),
        })
    }

    const fn range(lo: u128, hi: u128) -> EffectTarget {
        EffectTarget::Range {
            owner: OWNER,
            collection: CollectionId([4; 16]),
            lo,
            hi,
            cap: 8,
        }
    }

    const fn effect(target: EffectTarget, mode: Mode) -> Effect {
        Effect { target, mode }
    }

    /// The schedule itself, kind by kind, so a re-price is a diff here
    /// rather than an ordering that still happens to hold.
    #[test]
    fn every_kind_weighs_what_the_schedule_says() {
        let schedule = [
            (ModeKind::Read, 5),
            (ModeKind::Delta, 3),
            (ModeKind::Credit, 3),
            (ModeKind::Reserve, 3),
            (ModeKind::Write, 6),
        ];
        for (kind, weight) in schedule {
            assert_eq!(mode_weight(kind), weight, "{kind:?}");
        }
        assert_eq!(
            schedule.len(),
            ModeKind::ALL.len(),
            "a kind the schedule does not price",
        );
    }

    #[test]
    fn the_weight_ordering_is_the_lattice_ordering() {
        // write > read > {delta, credit, reserve}, off `compatible`.
        assert_eq!(mode_weight(ModeKind::Delta), mode_weight(ModeKind::Reserve));
        assert_eq!(mode_weight(ModeKind::Delta), mode_weight(ModeKind::Credit));
        assert!(mode_weight(ModeKind::Delta) > EXCLUSIVITY_FLOOR);
        assert!(mode_weight(ModeKind::Read) > mode_weight(ModeKind::Delta));
        assert!(mode_weight(ModeKind::Write) > mode_weight(ModeKind::Read));
    }

    #[test]
    fn order_bits_span_the_whole_space() {
        assert_eq!(order_bits(5, 5), 0, "one key spans nothing");
        assert_eq!(order_bits(9, 4), 0, "an inverted interval names nothing");
        assert_eq!(order_bits(0, 1), 1);
        assert_eq!(order_bits(0, u128::MAX), 128);
    }

    #[test]
    fn a_full_space_range_costs_more_than_a_narrow_one() {
        let narrow = effect_units(effect(range(100, 200), Mode::Write { moves: Moves::Both }));
        let full = effect_units(effect(
            range(0, u128::MAX),
            Mode::Write { moves: Moves::Both },
        ));
        assert!(full > narrow, "{full} should exceed {narrow}");
    }

    #[test]
    fn a_degenerate_range_spans_what_its_point_spans() {
        // One key is one leaf on the span axis; what still separates the
        // two is the depth axis, where an interval buys a scan and a
        // point buys one entry.
        assert_eq!(
            span_units(&range(42, 42)),
            span_units(&point(1)),
            "one key spans one leaf either way",
        );
        assert_eq!(
            effect_units(effect(range(42, 42), Mode::Write { moves: Moves::Both }))
                - depth_units(&range(42, 42)),
            effect_units(effect(point(1), Mode::Write { moves: Moves::Both }))
                - depth_units(&point(1)),
        );
    }

    /// A cap is execution work, and the price moves with it: two
    /// declarations differing only in their cap price apart, by exactly
    /// the entries the larger one may walk.
    #[test]
    fn two_declarations_differing_only_in_cap_price_apart() {
        let capped = |cap| EffectTarget::Range {
            owner: OWNER,
            collection: CollectionId([4; 16]),
            lo: 100,
            hi: 200,
            cap,
        };
        let (small, large) = (
            effect_units(effect(capped(8), Mode::Write { moves: Moves::Both })),
            effect_units(effect(capped(64), Mode::Write { moves: Moves::Both })),
        );
        assert_eq!(large - small, DEPTH_UNITS * (64 - 8));
    }

    /// The two axes price different claims: a full-space interval
    /// reading one entry is expensive on span (exclusion) and cheap on
    /// depth (work), and a narrow interval walking a large page is the
    /// reverse. Each figure below is computed off its own axis.
    #[test]
    fn span_prices_exclusion_and_depth_prices_the_walk() {
        let wide_shallow = EffectTarget::Range {
            owner: OWNER,
            collection: CollectionId([4; 16]),
            lo: 0,
            hi: u128::MAX,
            cap: 1,
        };
        let narrow_deep = EffectTarget::Range {
            owner: OWNER,
            collection: CollectionId([4; 16]),
            lo: 100,
            hi: 200,
            cap: 1024,
        };
        // Span: the wide claim excludes the whole order-key space.
        assert!(span_units(&wide_shallow) > span_units(&narrow_deep));
        // Depth: the deep claim buys the larger walk.
        assert!(depth_units(&narrow_deep) > depth_units(&wide_shallow));
    }

    /// An empty page is not free: the seek floor is charged before any
    /// entry, so even a cap of zero prices above nothing.
    #[test]
    fn a_scan_charges_its_seek_before_any_entry() {
        assert_eq!(
            depth_units(&range(100, 200)) - DEPTH_UNITS * 8,
            DEPTH_UNITS * SCAN_SEEK_ENTRIES as u64,
            "the fixture's cap of 8 rides above the seek floor",
        );
    }

    #[test]
    fn a_set_totals_its_effects() {
        let mut declared = EffectSet::new();
        declared
            .insert(effect(point(1), Mode::Write { moves: Moves::Both }))
            .unwrap();
        declared.insert(effect(range(0, 1023), Mode::Read)).unwrap();
        assert_eq!(
            footprint(&declared),
            effect_units(effect(point(1), Mode::Write { moves: Moves::Both }))
                + effect_units(effect(range(0, 1023), Mode::Read)),
        );
    }
}
