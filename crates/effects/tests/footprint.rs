//! The declared footprint's pricing properties: the quantity is monotone
//! in everything a sender can widen, and a function of the declaration
//! rather than of how it was assembled.
//!
//! The load-bearing one is monotonicity. A footprint that could fall as a
//! declaration grows would price looseness below precision, which inverts
//! the pressure the quantity exists to apply — and the specific inversion
//! it guards is a range spanning the whole order-key space costing what a
//! single entry costs, which is what conflict-by-interval-overlap makes
//! expensive for everyone else.

use hyperscale_vm_effects::{
    Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, LocalKey, Mode, ModeKind,
    SubstateKey, compatible, effect_units, footprint, mode_weight,
};
use proptest::collection::vec;
use proptest::prelude::{Just, Strategy, any, prop_oneof, proptest};

const KINDS: [ModeKind; 5] = [
    ModeKind::Read,
    ModeKind::Locked,
    ModeKind::Delta,
    ModeKind::Reserve,
    ModeKind::Write,
];

/// The mode kinds `kind` cannot share a key with.
fn excluded(kind: ModeKind) -> Vec<ModeKind> {
    KINDS
        .into_iter()
        .filter(|other| !compatible(kind, *other))
        .collect()
}

fn arb_mode() -> impl Strategy<Value = Mode> {
    prop_oneof![
        Just(Mode::Read),
        Just(Mode::Delta),
        Just(Mode::Write),
        any::<u128>().prop_map(|amount| Mode::Reserve { amount }),
        Just(Mode::Locked),
    ]
}

fn arb_target() -> impl Strategy<Value = EffectTarget> {
    prop_oneof![
        (any::<u8>(), any::<u8>()).prop_map(|(owner, local)| EffectTarget::Point(SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            local: LocalKey([local; 16]),
        })),
        (any::<u8>(), any::<u8>(), any::<u128>()).prop_map(|(owner, role, order)| {
            EffectTarget::Entry {
                owner: Address::new([owner; 31], AddressClass::Component),
                collection: CollectionId([role; 16]),
                order,
            }
        }),
        (
            any::<u8>(),
            any::<u8>(),
            any::<u128>(),
            any::<u128>(),
            any::<u32>()
        )
            .prop_map(|(owner, role, lo, hi, cap)| EffectTarget::Range {
                owner: Address::new([owner; 31], AddressClass::Component),
                collection: CollectionId([role; 16]),
                lo: lo.min(hi),
                hi: lo.max(hi),
                cap,
            }),
    ]
}

fn arb_effect() -> impl Strategy<Value = Effect> {
    (arb_target(), arb_mode()).prop_map(|(target, mode)| Effect { target, mode })
}

fn set_of(effects: &[Effect]) -> EffectSet {
    let mut declared = EffectSet::new();
    for effect in effects {
        // A folded reserve amount can overflow; such a set is not one a
        // sender can hold, so it is not one the price has to describe.
        if declared.insert(*effect).is_err() {
            break;
        }
    }
    declared
}

/// The weight ordering is the lattice's exclusion ordering, exhaustively:
/// a mode that excludes everything another does, and more, weighs more.
///
/// This is what ties the price to [`compatible`] rather than to a table
/// beside it — a lattice change that reordered exclusivity without moving
/// the weights would fail here.
#[test]
fn weight_respects_the_exclusion_ordering() {
    for narrow in KINDS {
        for wide in KINDS {
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

/// The inversion the quantity exists to foreclose: an interval over the
/// whole order-key space conflicts with every declaration on its
/// collection, so it must never price at what a narrow one prices at.
#[test]
fn the_whole_order_key_space_is_the_most_expensive_interval() {
    for kind in [Mode::Read, Mode::Delta, Mode::Write] {
        let whole = effect_units(Effect {
            target: EffectTarget::Range {
                owner: Address::new([1; 31], AddressClass::Component),
                collection: CollectionId([1; 16]),
                lo: 0,
                hi: u128::MAX,
                cap: 1,
            },
            mode: kind,
        });
        for (lo, hi) in [(0, 0), (5, 5), (0, 1023), (1 << 100, (1 << 100) + 4096)] {
            let narrower = effect_units(Effect {
                target: EffectTarget::Range {
                    owner: Address::new([1; 31], AddressClass::Component),
                    collection: CollectionId([1; 16]),
                    lo,
                    hi,
                    cap: u32::MAX,
                },
                mode: kind,
            });
            assert!(
                whole > narrower,
                "{kind:?}: [0, MAX] priced {whole}, [{lo}, {hi}] priced {narrower}",
            );
        }
    }
}

proptest! {
    /// Widening an interval never lowers its price. The cap moves with it
    /// and must not matter: a cap bounds execution, which fuel already
    /// meters, never the key space the declaration excludes.
    #[test]
    fn widening_an_interval_never_lowers_its_price(
        lo in any::<u128>(),
        span in any::<u128>(),
        growth in any::<u128>(),
        mode in arb_mode(),
        cap in any::<u32>(),
        wider_cap in any::<u32>(),
    ) {
        let hi = lo.saturating_add(span);
        let range = |hi, cap| Effect {
            target: EffectTarget::Range {
                owner: Address::new([2; 31], AddressClass::Component),
                collection: CollectionId([9; 16]),
                lo,
                hi,
                cap,
            },
            mode,
        };
        let narrow = effect_units(range(hi, cap));
        let wide = effect_units(range(hi.saturating_add(growth), wider_cap));
        assert!(wide >= narrow, "widening priced {wide} against {narrow}");
    }

    /// Declaring more never costs less: no sender lowers their footprint
    /// by widening their declaration.
    #[test]
    fn declaring_more_never_costs_less(
        effects in vec(arb_effect(), 0..12),
        extra in arb_effect(),
    ) {
        let declared = set_of(&effects);
        let mut grown = declared.clone();
        if grown.insert(extra).is_ok() {
            assert!(footprint(&grown) >= footprint(&declared));
        }
    }

    /// The price is a function of the declaration, not of the order it
    /// was assembled in — the same purity `route()` has, for the same
    /// reason: every node has to reach the identical number.
    #[test]
    fn the_price_is_a_function_of_the_set(effects in vec(arb_effect(), 0..12)) {
        let forward = set_of(&effects);
        let mut backward: Vec<Effect> = effects;
        backward.reverse();
        let backward = set_of(&backward);
        assert_eq!(forward, backward);
        assert_eq!(footprint(&forward), footprint(&backward));
    }

    /// A set totals its effects, so the fee schedule can price an effect
    /// in isolation and trust the sum.
    #[test]
    fn a_set_totals_its_effects(effects in vec(arb_effect(), 0..12)) {
        let declared = set_of(&effects);
        let summed: u64 = declared.iter().map(effect_units).sum();
        assert_eq!(footprint(&declared), summed);
    }
}
