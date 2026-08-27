//! What a failing test is told, pinned on the sentences.
//!
//! A decline is the most common failure a package author hits, and the
//! receipt carries it as a node index and a table index — so the harness
//! reads it back while the routed calls are in hand, and what a bare
//! `expect_completed` prints is the method and the name the package gave
//! the code, never `Declined { node, code }`.

use hyperscale_vm_fixtures::amm;
use hyperscale_vm_sdk::state::UnitFixed;
use hyperscale_vm_testing::{
    Chain, Outcome, PrincipalAddr, ResourceAddr, account, address_text, package, principal,
    resource,
};

const ALICE: PrincipalAddr = principal(1);
const X: ResourceAddr = resource(0xE1);
const Y: ResourceAddr = resource(0xE2);

/// A pool holding a thousand of each side, and Alice with the side she
/// sells.
fn pool(chain: &mut Chain) -> amm::Amm {
    chain.publish(package!(amm));
    let pool = chain.instantiate::<amm::Amm>(
        ALICE,
        amm::Settings {
            x: X,
            y: Y,
            fee: UnitFixed::bps(30).expect("thirty basis points is under one"),
        },
    );
    chain.credit(ALICE, X, 600);
    chain.credit(pool, X, 1_000);
    chain.credit(pool, Y, 1_000);
    pool
}

/// A swap whose floor no pool this size can reach.
fn declined(chain: &mut Chain, pool: amm::Amm) -> Outcome<()> {
    chain.transact(ALICE, |b| {
        let signed_in = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, signed_in, X, 500)?;
        let bought = pool.swap(b, funds, 100_000u128)?;
        account::deposit(b, ALICE, bought)
    })
}

/// The sentence names the method and the error, not the coordinates.
#[test]
fn a_decline_reads_as_the_method_and_the_named_error() {
    let mut chain = Chain::native();
    let pool = pool(&mut chain);
    let outcome = declined(&mut chain, pool);

    assert_eq!(outcome.declined_as(), Some("slippage-exceeded"));
    outcome.expect_declined(amm::Error::SlippageExceeded);
    let sentence = outcome.refused_as();
    assert!(sentence.contains("`swap`"), "{sentence}");
    assert!(sentence.contains("slippage-exceeded"), "{sentence}");
    assert!(!sentence.contains("Declined {"), "{sentence}");
}

/// A decline of the wrong variant panics naming both sides.
#[test]
#[should_panic(expected = "expected a decline of `empty-pool`")]
fn expect_declined_names_what_happened_instead() {
    let mut chain = Chain::native();
    let pool = pool(&mut chain);
    declined(&mut chain, pool).expect_declined(amm::Error::EmptyPool);
}

/// The same sentence is what `expect_completed` panics with.
#[test]
#[should_panic(expected = "slippage-exceeded")]
fn expect_completed_names_the_decline() {
    let mut chain = Chain::native();
    let pool = pool(&mut chain);
    declined(&mut chain, pool).expect_completed();
}

/// An under-covered reservation names the vault, not the leaf hash.
#[test]
fn an_infeasible_movement_reads_as_the_vault_it_missed() {
    let mut chain = Chain::native();
    let pool = pool(&mut chain);
    let outcome = chain.transact(ALICE, |b| {
        let signed_in = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, signed_in, X, 5_000)?;
        let bought = pool.swap(b, funds, 1u128)?;
        account::deposit(b, ALICE, bought)
    });

    let sentence = outcome.refused_as();
    assert!(sentence.contains("the vault of"), "{sentence}");
    assert!(sentence.contains(&address_text(X.address())), "{sentence}");
    assert!(
        sentence.contains(&address_text(ALICE.address())),
        "{sentence}"
    );
    assert!(sentence.contains("short"), "{sentence}");
    assert!(!sentence.contains("SubstateKey"), "{sentence}");
}
