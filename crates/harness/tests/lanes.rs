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

use hyperscale_vm_effects::{AdmissionError, EvalError, TestHasher, child_key, instance_data_key};
use hyperscale_vm_fixtures::amm::{self, Settings};
use hyperscale_vm_fixtures::grammar;
use hyperscale_vm_harness::fixtures::repo_root;
use hyperscale_vm_kernel::Receipt;
use hyperscale_vm_sdk::hbor::{from_slice, to_vec};
use hyperscale_vm_sdk::state::UnitFixed;
use hyperscale_vm_testing::{
    Chain, Package, PrincipalAddr, Refused, ResourceAddr, account, principal, resource,
};
use hyperscale_vm_types::{Outcome, Presence, UnmetCondition};

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
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, ());
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
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, ());
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
        let shapes = chain.instantiate::<grammar::Grammar>(ALICE, ());
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
