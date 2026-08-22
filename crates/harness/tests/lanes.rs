//! The author's two lanes, over one text.
//!
//! A [`Chain`] says nothing about which engine runs it, so the same test
//! holds for both — and what this asserts is that they agree. Not on
//! everything: fuel is the engine's own figure and the native lane has
//! none. On everything a contract is about — the outcome, the state it
//! moved, and what it said happened.
//!
//! That agreement is what makes the fast lane worth trusting. An author
//! writes against the bodies; a network runs the artifact; if the two
//! could differ silently, the loop would be a comfort rather than a
//! check.

use hyperscale_vm_effects::{
    AdmissionError, EvalError, TestHasher, Value, child_key, instance_data_key,
};
use hyperscale_vm_fixtures::amm::{self, Settings};
use hyperscale_vm_fixtures::grammar;
use hyperscale_vm_harness::fixtures::repo_root;
use hyperscale_vm_kernel::Receipt;
use hyperscale_vm_sdk::hbor::{from_slice, to_vec};
use hyperscale_vm_sdk::state::{Table, UnitFixed};
use hyperscale_vm_testing::{
    Chain, Package, PrincipalAddr, Refused, ResourceAddr, account, principal, resource,
};
use hyperscale_vm_types::{Answer, Outcome, Presence, UnmetCondition};

const ALICE: PrincipalAddr = principal(0x41);
const X: ResourceAddr = resource(0xE1);
const Y: ResourceAddr = resource(0xE2);

/// The pool package, rooted at the crate its artifact is built from.
///
/// Written out rather than taken from `package!`, which reads the crate
/// it is written in — and this is not that crate.
fn amm() -> Package {
    Package::new(
        amm::metadata(),
        repo_root().join("guests").join("amm"),
        amm::invoke,
    )
}

/// The schedule every shapes instance is created under: two named
/// tiers, a fee for everything the schedule does not name, and the two
/// parties a `for-each` writes a clause each for.
fn terms() -> grammar::Terms {
    grammar::Terms {
        tiers: Table::new(vec![(1, 10), (2, 20)]),
        fallback: 7,
        sides: vec![principal(0x51).into(), principal(0x52).into()],
    }
}

/// The shapes package, rooted at the crate its artifact is built from.
fn grammar() -> Package {
    Package::new(
        grammar::metadata(),
        repo_root().join("guests").join("grammar"),
        grammar::invoke,
    )
}

/// A pool with a thousand of each side, and Alice holding six hundred.
fn pool(mut chain: Chain) -> (Chain, amm::Amm) {
    chain.publish(amm());
    let pool = chain.instantiate::<amm::Amm>(
        ALICE,
        Settings {
            x: X,
            y: Y,
            fee: UnitFixed::bps(30).expect("thirty basis points is under one"),
        },
    );
    chain.credit(ALICE, X, 600);
    chain.credit(pool, X, 1_000);
    chain.credit(pool, Y, 1_000);
    (chain, pool)
}

/// One swap, and what each lane made of it.
fn swap(chain: Chain, floor: u128) -> (Receipt, [u128; 4]) {
    let (mut chain, pool) = pool(chain);
    let outcome = chain.transact(ALICE, |b| {
        let signed_in = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, signed_in, X, 500)?;
        let bought = pool.swap(b, funds, floor)?;
        account::deposit(b, ALICE, bought)
    });
    let receipt = outcome.receipt().clone();
    let balances = [
        chain.balance(pool, X),
        chain.balance(pool, Y),
        chain.balance(ALICE, X),
        chain.balance(ALICE, Y),
    ];
    (receipt, balances)
}

/// What the lanes are held to: the receipt, less the one figure only an
/// engine can produce.
///
/// Named as the exclusion rather than as a list of what to compare, so a
/// field a receipt gains is held to both lanes without anyone having to
/// remember it here.
fn comparable(receipt: &Receipt) -> Receipt {
    Receipt {
        fuel: 0,
        ..receipt.clone()
    }
}

#[test]
fn a_completed_swap_reads_the_same_in_both_lanes() {
    let (native, native_balances) = swap(Chain::native(), 300);
    let (blessed, blessed_balances) = swap(Chain::wasm(), 300);

    assert_eq!(comparable(&native), comparable(&blessed), "lanes diverged");
    assert_eq!(native_balances, blessed_balances, "state diverged");
    assert_eq!(native_balances, [1_500, 668, 100, 332]);
}

/// The declared refusal reaches both the same way: a code the package
/// published, not a trap, and nothing moved.
#[test]
fn a_declined_swap_reads_the_same_in_both_lanes() {
    let (native, native_balances) = swap(Chain::native(), 400);
    let (blessed, blessed_balances) = swap(Chain::wasm(), 400);

    assert_eq!(comparable(&native), comparable(&blessed), "lanes diverged");
    assert_eq!(native_balances, blessed_balances, "state diverged");
    assert_eq!(
        native_balances,
        [1_000, 1_000, 600, 0],
        "a decline moves nothing"
    );
}

/// The account's own surface, with no package published at all: a
/// transfer is the one path every chain has, and the two engines run it
/// off the same committed blob and the same module.
#[test]
fn a_transfer_reads_the_same_in_both_lanes() {
    let bob = principal(0x42);
    let run = |mut chain: Chain| {
        chain.credit(ALICE, X, 100);
        let outcome = chain.transact(ALICE, |b| {
            let signed_in = account::authorize(b, ALICE)?;
            let funds = account::withdraw(b, signed_in, X, 40)?;
            account::deposit(b, bob, funds)
        });
        let receipt = outcome.receipt().clone();
        (receipt, [chain.balance(ALICE, X), chain.balance(bob, X)])
    };

    let (native, native_balances) = run(Chain::native());
    let (blessed, blessed_balances) = run(Chain::wasm());

    assert_eq!(comparable(&native), comparable(&blessed), "lanes diverged");
    assert_eq!(native_balances, blessed_balances, "state diverged");
    assert_eq!(native_balances, [60, 40]);
}

/// A fielded mint and the read of what it filed agree across the lanes.
///
/// The one shape a host build cannot settle on its own: the write and
/// the read are each a cfg with a guest half and a host half, and a
/// native run reads only the host one. So the cell a mint files on wasm
/// and the value a read decodes there are held to what the bodies did.
#[test]
fn a_fielded_instance_reads_the_same_in_both_lanes() {
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, terms());
        let outcome = chain.transact(ALICE, |b| {
            let seat = shapes.seat(b, 3, 42)?;
            account::deposit_nf(b, ALICE, seat)
        });
        let receipt = outcome.receipt().clone();
        let seat = shapes.issued_seat(&TestHasher);
        let filed = chain.cell(instance_data_key(&TestHasher, shapes, seat, 3));
        (receipt, filed)
    };

    let (native, native_filed) = run(Chain::native());
    let (blessed, blessed_filed) = run(Chain::wasm());

    assert_eq!(comparable(&native), comparable(&blessed), "lanes diverged");
    assert_eq!(native_filed, blessed_filed, "the filed record diverged");
    assert_eq!(
        native_filed,
        Some(to_vec(&grammar::Seat { holder: 42 }).expect("the record encodes")),
        "the cell holds the record the mark declares",
    );
}

/// A closure the lowering can see through declares what the same
/// arithmetic declares without one.
///
/// The rule is about the effect rather than the syntax: a closure that
/// opens no site and produces no edge has nothing to attribute, so the
/// declaration is the one the long way round produces — checked by
/// comparing the two rather than by reading either.
#[test]
fn a_closure_over_a_value_in_hand_declares_what_the_long_way_does() {
    let methods = &grammar::metadata().methods;
    let folded = &methods["tally"];
    let spelled = &methods["tally-plainly"];

    assert_eq!(folded.effects, spelled.effects, "the clauses diverged");
    assert_eq!(folded.abi, spelled.abi, "the binding diverged");
    assert_eq!(folded.params, spelled.params);
    assert_eq!(folded.outputs, spelled.outputs);

    // And both halves run it: the fold is the guest's own arithmetic,
    // so the cell it writes is what the closure computed.
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, terms());
        chain
            .transact(ALICE, |b| shapes.tally(b, 41))
            .expect_completed();
        chain
            .cell(child_key(&TestHasher, shapes, grammar::NOTED, &[]))
            .map(|bytes| from_slice::<u64>(&bytes).expect("the cell holds what the field does"))
    };

    let native = run(Chain::native());
    let blessed = run(Chain::wasm());
    assert_eq!(native, blessed, "lanes diverged");
    assert_eq!(native, Some(42), "the closure folded what it was handed");
}

/// A method handing back an ordinary value.
///
/// The value is not an edge, so it is not an output: a manifest naming
/// this node's output has none to name, and the value rides the receipt
/// instead — which is where the caller reads it, in both lanes.
#[test]
fn a_view_method_answers_off_the_receipt_in_both_lanes() {
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, terms());
        // `seat` notes the holder it filed, so there is something to read
        // back that the transaction itself put there.
        chain
            .transact(ALICE, |b| {
                let minted = shapes.seat(b, 3, 42)?;
                account::deposit_nf(b, ALICE, minted)
            })
            .expect_completed();
        let outcome = chain.transact(ALICE, |b| shapes.noted(b));
        // And the value is not an output: a node naming one has none.
        let routed = chain
            .try_transact(ALICE, |b| {
                let value = b.call(shapes, "noted", ())?.one()?;
                account::deposit(b, ALICE, value)
            })
            .err();
        (outcome.receipt().outcome.clone(), routed.is_some())
    };

    let (native, native_routed) = run(Chain::native());
    let (blessed, blessed_routed) = run(Chain::wasm());

    assert_eq!(native, blessed, "lanes diverged");
    assert!(
        native_routed && blessed_routed,
        "an answer is not an output a manifest can consume",
    );
    let Outcome::Completed { answers } = &native else {
        panic!("the view method completes: {native:?}");
    };
    assert_eq!(
        answers.as_slice(),
        [Answer {
            node: 0,
            value: to_vec(&42u64).expect("a scalar encodes"),
        }],
        "the receipt carries what the method answered",
    );
}

/// A configured table read where the declaration evaluates it, in both
/// lanes.
///
/// The bare lookup and the guarded one over the same table: the first is
/// the read a body writes when the schedule is total, the second is what
/// it writes when a miss should answer rather than refuse. What the
/// guest holds either way is the fee, never the rows.
#[test]
fn a_configured_table_is_read_the_same_in_both_lanes() {
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, terms());
        let noted = |chain: &Chain| {
            chain
                .cell(child_key(&TestHasher, shapes, grammar::NOTED, &[]))
                .map(|bytes| from_slice::<u64>(&bytes).expect("the cell holds what the field does"))
        };

        chain
            .transact(ALICE, |b| shapes.charge(b, 2))
            .expect_completed();
        let scheduled = noted(&chain);
        // A tier the schedule does not name: the lookup misses where the
        // declaration is evaluated, so the transaction never admits.
        let missed = chain
            .try_transact(ALICE, |b| shapes.charge(b, 9))
            .err()
            .is_some();

        chain
            .transact(ALICE, |b| shapes.charge_or(b, 9))
            .expect_completed();
        let defaulted = noted(&chain);
        chain
            .transact(ALICE, |b| shapes.charge_or(b, 1))
            .expect_completed();
        let guarded = noted(&chain);

        chain
            .transact(ALICE, |b| shapes.scheduled(b, 1))
            .expect_completed();
        let known = noted(&chain);
        chain
            .transact(ALICE, |b| shapes.scheduled(b, 9))
            .expect_completed();
        let unknown = noted(&chain);

        chain
            .transact(ALICE, |b| shapes.later(b, 5, 8))
            .expect_completed();
        let projected = noted(&chain);

        // `tallied` reads the cell inside a `vec!` and writes it after,
        // so what it lands on is the fee, what `later` left, and the
        // literal beside them.
        chain
            .transact(ALICE, |b| shapes.tallied(b, 1))
            .expect_completed();
        let tallied = noted(&chain);

        (
            scheduled, missed, defaulted, guarded, known, unknown, projected, tallied,
        )
    };

    let native = run(Chain::native());
    let blessed = run(Chain::wasm());

    assert_eq!(native, blessed, "lanes diverged");
    let (scheduled, missed, defaulted, guarded, known, unknown, projected, tallied) = native;
    assert_eq!(scheduled, Some(20), "the fee the schedule names");
    assert!(missed, "an unscheduled tier never admits");
    assert_eq!(defaulted, Some(7), "the fee the package chose");
    assert_eq!(guarded, Some(10), "the guarded read still finds the row");
    assert_eq!(known, Some(1), "the schedule names this tier");
    assert_eq!(unknown, Some(0), "and does not name that one");
    assert_eq!(projected, Some(8), "the second component of the pair");
    assert_eq!(
        tallied,
        Some(10 + 8 + 1),
        "the read inside the macro is the cell the write left",
    );
}

/// What one configured party's leaf holds under `shapes`.
fn owed(chain: &Chain, shapes: grammar::Grammar, party: PrincipalAddr) -> Option<u64> {
    chain
        .cell(child_key(
            &TestHasher,
            shapes,
            grammar::OWED,
            &[Value::Address(party.into()).canonical_bytes()],
        ))
        .map(|bytes| from_slice::<u64>(&bytes).expect("the cell holds what the field does"))
}

/// A `for-each` executed through its run, in both lanes.
///
/// The declaration writes one clause per configured party and the guest
/// walks the run those expansions materialised — so what the body
/// touches is what the declaration said, at a width neither the
/// signature nor the guest chose.
#[test]
fn a_for_each_executes_through_its_run_in_both_lanes() {
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, terms());
        chain
            .transact(ALICE, |b| shapes.spread(b, 5))
            .expect_completed();
        let spread = (
            owed(&chain, shapes, principal(0x51)),
            owed(&chain, shapes, principal(0x52)),
        );
        // The guard holds for the second party alone, so the first keeps
        // what the unguarded loop left it.
        chain
            .transact(ALICE, |b| shapes.spread_to(b, 9, principal(0x52)))
            .expect_completed();
        (
            spread.0,
            spread.1,
            owed(&chain, shapes, principal(0x51)),
            owed(&chain, shapes, principal(0x52)),
            owed(&chain, shapes, ALICE),
        )
    };

    let native = run(Chain::native());
    let blessed = run(Chain::wasm());

    assert_eq!(native, blessed, "lanes diverged");
    let (first, second, skipped, guarded, unnamed) = native;
    assert_eq!(first, Some(5), "the first configured party");
    assert_eq!(second, Some(5), "and the second");
    assert_eq!(
        skipped,
        Some(5),
        "the guarded row did not fire here, so the leaf holds what the first loop left",
    );
    assert_eq!(
        guarded,
        Some(9),
        "and it did fire for the element the condition held for",
    );
    assert_eq!(
        unnamed, None,
        "a party the configuration does not name is a clause the loop never declared",
    );
}

/// A loop over a list of one and a list of none, in both lanes.
///
/// The width is the instance's, so the two edges of it are two
/// instances: one whose run covers a single element, and one whose run
/// covers nothing and whose guest walks no iterations at all.
#[test]
fn a_run_covers_a_list_of_one_and_a_list_of_none_in_both_lanes() {
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let sole = chain.instantiate::<grammar::Grammar>(
            ALICE,
            grammar::Terms {
                tiers: Table::new(vec![(1, 10)]),
                fallback: 7,
                sides: vec![principal(0x51).into()],
            },
        );
        let none = chain.instantiate::<grammar::Grammar>(
            ALICE,
            grammar::Terms {
                tiers: Table::new(vec![(1, 10)]),
                fallback: 7,
                sides: Vec::new(),
            },
        );
        chain
            .transact(ALICE, |b| sole.spread(b, 3))
            .expect_completed();
        chain
            .transact(ALICE, |b| none.spread(b, 3))
            .expect_completed();
        (
            owed(&chain, sole, principal(0x51)),
            owed(&chain, none, principal(0x51)),
        )
    };

    let native = run(Chain::native());
    let blessed = run(Chain::wasm());

    assert_eq!(native, blessed, "lanes diverged");
    let (one, empty) = native;
    assert_eq!(one, Some(3), "the single element the run covers");
    assert_eq!(empty, None, "a run over nothing writes nothing");
}

/// The configuration record passed on whole, in both lanes.
///
/// What crosses is the fields the kernel evaluated, assembled under the
/// name the package gave them — so a helper over the settings reads what
/// a projection of them would have read, and nothing decodes the leaf.
#[test]
fn a_configuration_record_reaches_a_helper_in_both_lanes() {
    let run = |chain: Chain| {
        let (mut chain, pool) = pool(chain);
        let asked = |chain: &mut Chain, resource: ResourceAddr| {
            chain
                .transact(ALICE, |b| pool.trades(b, resource))
                .receipt()
                .outcome
                .clone()
        };
        (asked(&mut chain, X), asked(&mut chain, resource(0xE9)))
    };

    let native = run(Chain::native());
    let blessed = run(Chain::wasm());

    assert_eq!(native, blessed, "lanes diverged");
    let (side, stranger) = native;
    let answered = |outcome: &Outcome, judgment: bool| {
        let Outcome::Completed { answers } = outcome else {
            panic!("the view method completes: {outcome:?}");
        };
        answers.as_slice()
            == [Answer {
                node: 0,
                value: to_vec(&judgment).expect("a judgment encodes"),
            }]
    };
    assert!(answered(&side, true), "the configured side: {side:?}");
    assert!(
        answered(&stranger, false),
        "a resource the pair does not name: {stranger:?}",
    );
}

/// An instance's record changing, between the two ends of its life.
///
/// The mint's door read the other way round: a rewrite requires the leaf
/// present, so the two cases that have no live instance to change — one
/// nothing minted, and one a burn retired — are the same refusal, and
/// both land before the body runs.
#[test]
fn an_instance_rewrites_only_while_it_is_live_in_both_lanes() {
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, terms());
        let seat = shapes.issued_seat(&TestHasher);
        let reseat =
            |chain: &mut Chain, holder: u64| chain.transact(ALICE, |b| shapes.reseat(b, 3, holder));

        let unminted = reseat(&mut chain, 7).refused().cloned();
        chain
            .transact(ALICE, |b| {
                let minted = shapes.seat(b, 3, 42)?;
                account::deposit_nf(b, ALICE, minted)
            })
            .expect_completed();

        reseat(&mut chain, 99).expect_completed();
        let filed = chain.cell(instance_data_key(&TestHasher, shapes, seat, 3));
        let noted = chain
            .cell(child_key(&TestHasher, shapes, grammar::NOTED, &[]))
            .map(|bytes| from_slice::<u64>(&bytes).expect("the cell holds what the field does"));

        chain
            .transact(ALICE, |b| {
                let signed_in = account::authorize(b, ALICE)?;
                let edge = account::withdraw_nf(b, signed_in, seat, &[3])?;
                shapes.unseat(b, edge)
            })
            .expect_completed();
        let retired = reseat(&mut chain, 7).refused().cloned();
        (unminted, filed, noted, retired)
    };

    let (native_unminted, native_filed, native_noted, native_retired) = run(Chain::native());
    let (blessed_unminted, blessed_filed, blessed_noted, blessed_retired) = run(Chain::wasm());

    let unmet_presence = |refusal: &Option<Outcome>| {
        matches!(
            refusal,
            Some(Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    required: Presence::Present,
                    ..
                },
            })
        )
    };
    assert!(
        unmet_presence(&native_unminted) && unmet_presence(&blessed_unminted),
        "an id nothing minted has no record to change: {native_unminted:?}",
    );
    assert!(
        unmet_presence(&native_retired) && unmet_presence(&blessed_retired),
        "and neither has one a burn retired: {native_retired:?}",
    );
    assert_eq!(
        (&native_filed, native_noted),
        (&blessed_filed, blessed_noted)
    );
    assert_eq!(
        native_filed,
        Some(to_vec(&grammar::Seat { holder: 99 }).expect("the record encodes")),
        "the cell holds what the rewrite filed",
    );
    assert_eq!(native_noted, Some(99), "and the body read it back");
}

/// An instance retiring, and the id coming free with it.
///
/// The cell and the holding go together — one call, one instance, and
/// the issuer's state back where it started. What the protocol keeps
/// saying is the narrower thing the mint's door already said: a *live*
/// instance refuses a second mint at its id, and a retired one does not.
#[test]
fn a_burned_instance_frees_its_cell_and_its_id_in_both_lanes() {
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, terms());
        let seat = shapes.issued_seat(&TestHasher);
        let filed = |chain: &Chain| chain.cell(instance_data_key(&TestHasher, shapes, seat, 3));

        let mint = |chain: &mut Chain, holder: u64| {
            chain.transact(ALICE, |b| {
                let minted = shapes.seat(b, 3, holder)?;
                account::deposit_nf(b, ALICE, minted)
            })
        };
        mint(&mut chain, 42).expect_completed();
        // A live instance still refuses a second mint at its id.
        let live = mint(&mut chain, 43).refused().cloned();

        chain
            .transact(ALICE, |b| {
                let signed_in = account::authorize(b, ALICE)?;
                let edge = account::withdraw_nf(b, signed_in, seat, &[3])?;
                shapes.unseat(b, edge)
            })
            .expect_completed();
        let retired = (filed(&chain), chain.holds(ALICE, seat, 3));

        // And the id is an ordinary free id again.
        mint(&mut chain, 44).expect_completed();
        (live, retired, filed(&chain), chain.holds(ALICE, seat, 3))
    };

    let (native_live, native_retired, native_filed, native_holds) = run(Chain::native());
    let (blessed_live, blessed_retired, blessed_filed, blessed_holds) = run(Chain::wasm());

    let unmet_absence = |refusal: &Option<Outcome>| {
        matches!(
            refusal,
            Some(Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    required: Presence::Absent,
                    ..
                },
            })
        )
    };
    assert!(
        unmet_absence(&native_live) && unmet_absence(&blessed_live),
        "a live instance refuses a second mint: {native_live:?} / {blessed_live:?}",
    );
    assert_eq!(native_retired, blessed_retired, "the burn diverged");
    assert_eq!(
        native_retired,
        (None, false),
        "the burn left neither a data cell nor a holding",
    );
    assert_eq!(
        (&native_filed, native_holds),
        (&blessed_filed, blessed_holds)
    );
    assert_eq!(
        native_filed,
        Some(to_vec(&grammar::Seat { holder: 44 }).expect("the record encodes")),
        "the re-mint filed its own record at the freed id",
    );
    assert!(native_holds, "and the holder holds it again");
}

/// The instance an edge carries, read with no id in the call.
///
/// The declaration names the sole element of the edge's id list, so
/// both lanes reach the same cell and neither is told which one by the
/// caller. The edges that name no one instance are the same question
/// answered before either body runs: an edge carrying two and an edge
/// carrying none fail the evaluation, so they are refused rather than
/// trapped.
#[test]
fn the_instance_an_edge_carries_reads_the_same_in_both_lanes() {
    let run = |mut chain: Chain| {
        chain.publish(grammar());
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, terms());
        let seat = shapes.issued_seat(&TestHasher);
        // Two seats, so the last mint's own read leaves `noted` holding
        // a holder the edge read has to overwrite to be seen.
        for (id, holder) in [(3u64, 42u64), (4, 43)] {
            chain
                .transact(ALICE, |b| {
                    let minted = shapes.seat(b, id, holder)?;
                    account::deposit_nf(b, ALICE, minted)
                })
                .expect_completed();
        }

        let read = |chain: &mut Chain, ids: &[u64]| {
            chain.try_transact(ALICE, |b| {
                let signed_in = account::authorize(b, ALICE)?;
                let edge = account::withdraw_nf(b, signed_in, seat, ids)?;
                let handed_back = shapes.seated(b, edge)?;
                account::deposit_nf(b, ALICE, handed_back)
            })
        };

        let one = read(&mut chain, &[3]).expect("an edge carrying one instance names it");
        let noted = chain
            .cell(child_key(&TestHasher, shapes, grammar::NOTED, &[]))
            .map(|bytes| from_slice::<u64>(&bytes).expect("the cell holds what the field does"));
        // How many instances the refusal said the edge carried, where
        // it was refused for carrying the wrong number of them.
        let counted = |refused: Option<Refused>| match refused {
            Some(Refused::Admission(AdmissionError::Eval {
                source: EvalError::NotSingleton { len },
                ..
            })) => Some(len),
            other => panic!("an edge naming no one instance is refused: {other:?}"),
        };
        let two = counted(read(&mut chain, &[3, 4]).err());
        let none = counted(read(&mut chain, &[]).err());
        (one.receipt().clone(), noted, two, none)
    };

    let (native, native_noted, native_two, native_none) = run(Chain::native());
    let (blessed, blessed_noted, blessed_two, blessed_none) = run(Chain::wasm());

    assert_eq!(comparable(&native), comparable(&blessed), "lanes diverged");
    assert_eq!(native_noted, blessed_noted, "the read record diverged");
    assert_eq!(native_noted, Some(42), "the edge named the seat it carried");
    assert_eq!((native_two, native_none), (blessed_two, blessed_none));
    assert_eq!(native_two, Some(2), "an edge carrying two names neither");
    assert_eq!(native_none, Some(0), "an edge carrying none names nothing");
}
