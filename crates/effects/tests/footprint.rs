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

use hyperscale_vm_effects::{effect_units, footprint};
use hyperscale_vm_types::{
    Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, LocalKey, Mode, Moves,
    SubstateKey,
};
use proptest::collection::vec;
use proptest::prelude::{Just, Strategy, any, prop_oneof, proptest};

fn arb_mode() -> impl Strategy<Value = Mode> {
    prop_oneof![
        Just(Mode::Read),
        Just(Mode::Delta { moves: Moves::Both }),
        Just(Mode::Write { moves: Moves::Both }),
        any::<u128>().prop_map(|amount| Mode::Reserve { amount }),
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
/// The inversion the span axis exists to foreclose: an interval over the
/// whole order-key space conflicts with every declaration on its
/// collection, so at any given cap it must never price at what a narrow
/// one prices at. The comparison holds the cap fixed because the cap
/// buys a different thing — a narrow interval walking a large page may
/// out-price a wide one reading a single entry, and that is the depth
/// axis working rather than this property failing.
#[test]
fn the_whole_order_key_space_is_the_most_expensive_interval() {
    for kind in [
        Mode::Read,
        Mode::Delta { moves: Moves::Both },
        Mode::Write { moves: Moves::Both },
    ] {
        for cap in [0, 1, 1024, u32::MAX] {
            let whole = effect_units(Effect {
                target: EffectTarget::Range {
                    owner: Address::new([1; 31], AddressClass::Component),
                    collection: CollectionId([1; 16]),
                    lo: 0,
                    hi: u128::MAX,
                    cap,
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
                        cap,
                    },
                    mode: kind,
                });
                assert!(
                    whole > narrower,
                    "{kind:?}: [0, MAX] priced {whole}, [{lo}, {hi}] priced {narrower} at cap {cap}",
                );
            }
        }
    }
}

proptest! {
    /// Widening an interval, raising its cap, or both, never lowers its
    /// price: the two axes are each monotone, so no sender lowers their
    /// footprint by asking for more of either.
    #[test]
    fn widening_an_interval_never_lowers_its_price(
        lo in any::<u128>(),
        span in any::<u128>(),
        growth in any::<u128>(),
        mode in arb_mode(),
        cap in any::<u32>(),
        cap_growth in any::<u32>(),
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
        let wide = effect_units(range(
            hi.saturating_add(growth),
            cap.saturating_add(cap_growth),
        ));
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

/// A move of more instances prices above a move of fewer, through the
/// vocabulary's own shape: a holdings interval's cap is the count of
/// the ids the call names, and the cap is charged as depth — so the
/// price of a withdrawal is a function of the instances it moves.
#[test]
fn a_move_of_more_instances_prices_above_fewer() {
    use hyperscale_vm_effects::dsl::{Clause, ModeExpr};
    use hyperscale_vm_effects::{
        DEPTH_UNITS, EvalBudget, EvalInputs, Expr, Hash32, InstanceMeta, ManifestHash, PackageHash,
        PresentedGrants, TestHasher, Value, evaluate_effects, holdings_range,
    };

    let holder = Address::new([3; 31], AddressClass::Component);
    let resource = Address::new([4; 31], AddressClass::Resource);
    // The withdrawal's shape: the resource and the ids are arguments,
    // and the cap is the count of the ids named.
    let moved = |ids: &[u64]| {
        let clauses = [Clause::Effect {
            reach: None,
            guard: None,
            target: holdings_range(Expr::Arg(0), Expr::Len(Box::new(Expr::Arg(1)))),
            mode: ModeExpr::Write { moves: Moves::Both },
            denomination: None,
        }];
        let args = [
            Value::Address(resource),
            Value::List(ids.iter().copied().map(Value::U64).collect()),
        ];
        let record = InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: Vec::new(),
            salt: Hash32([2; 32]),
        };
        let budget = EvalBudget::default();
        let inputs = EvalInputs {
            self_addr: holder,
            args: &args,
            record: &record,
            node_index: 0,
            identity: ManifestHash(Hash32([7; 32])),
            grants: PresentedGrants::none(),
            budget: &budget,
        };
        footprint(&evaluate_effects(&clauses, &inputs, &TestHasher).unwrap())
    };
    let (few, many) = (moved(&[1, 2]), moved(&[1, 2, 3, 4, 5]));
    assert_eq!(many - few, DEPTH_UNITS * 3, "three more instances walked");
}
