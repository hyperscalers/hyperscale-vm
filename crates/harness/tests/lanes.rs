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

use hyperscale_vm_fixtures::amm;
use hyperscale_vm_harness::fixtures::repo_root;
use hyperscale_vm_kernel::Receipt;
use hyperscale_vm_testing::{
    Chain, ComponentAddr, Package, PrincipalAddr, ResourceAddr, account, principal, resource,
};

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

/// A pool with a thousand of each side, and Alice holding six hundred.
fn pool(mut chain: Chain) -> (Chain, ComponentAddr) {
    let amm = chain.publish(amm());
    let pool = chain.instantiate(amm, (X, Y, 30u64));
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
        let bought = b.call(pool, "swap", (funds, floor))?.one()?;
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
