//! The pool's own test: a swap, against the real kernel.

use hyperscale_vm_testing::{
    Chain, ComponentAddr, PrincipalAddr, ResourceAddr, account, package, principal, resource,
};

const ALICE: PrincipalAddr = principal(1);
const X: ResourceAddr = resource(0xE1);
const Y: ResourceAddr = resource(0xE2);
/// Thirty basis points, at the scale the pool's bounded fee type holds.
const FEE: u128 = 30 * (1_000_000_000_000_000_000 / 10_000);

/// A pool holding a thousand of each side at 30 bps, and Alice with six
/// hundred of the side she sells.
fn pool() -> (Chain, ComponentAddr) {
    let mut chain = Chain::native();
    let amm = chain.publish(package!(amm_guest::amm));
    let pool = chain.instantiate(amm, (X, Y, FEE));
    chain.credit(ALICE, X, 600);
    chain.credit(pool, X, 1_000);
    chain.credit(pool, Y, 1_000);
    (chain, pool)
}

/// A trade moves along the constant-product curve, net of the fee.
///
/// The arithmetic is computed here rather than read off the body: 30 bps
/// on 500 leaves 498 effective, and 1000 * 498 / 1498 is 332.
#[test]
fn a_swap_pays_the_curve_less_the_fee() {
    let (mut chain, pool) = pool();

    chain
        .transact(ALICE, |b| {
            let signed_in = account::authorize(b, ALICE)?;
            let funds = account::withdraw(b, signed_in, X, 500)?;
            let bought = b.call(pool, "swap", (funds, 300u128))?.one()?;
            account::deposit(b, ALICE, bought)
        })
        .expect_completed();

    assert_eq!(chain.balance(pool, X), 1_500);
    assert_eq!(chain.balance(pool, Y), 668);
    assert_eq!(chain.balance(ALICE, X), 100);
    assert_eq!(chain.balance(ALICE, Y), 332);
}

/// A floor the trade cannot reach is declined, not trapped: the sender
/// lost a race rather than committing a defect, so the pool says so with
/// its own error and nothing moves.
#[test]
fn a_floor_the_pool_cannot_reach_declines() {
    let (mut chain, pool) = pool();

    let outcome = chain.transact(ALICE, |b| {
        let signed_in = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, signed_in, X, 500)?;
        let bought = b.call(pool, "swap", (funds, 400u128))?.one()?;
        account::deposit(b, ALICE, bought)
    });

    assert_eq!(outcome.declined_as(), Some("slippage-exceeded"));
    assert_eq!(chain.balance(ALICE, X), 600, "a decline moves nothing");
    assert_eq!(chain.balance(pool, X), 1_000);
}

/// A reserve that used to overflow the curve now pays out of it.
///
/// The pool's old arithmetic multiplied `y` by `dx` and guarded the
/// result with `checked_mul().unwrap()`, so a Y side anywhere near the
/// amount width made the swap trap rather than answer. Re-associated as
/// a share of `y`, the same trade has nothing to overflow: the share is
/// bounded below one and the product is held whole inside a single
/// division. The reserve here is the largest one there is.
#[test]
fn a_reserve_that_once_overflowed_the_curve_now_trades() {
    let mut chain = Chain::native();
    let amm = chain.publish(package!(amm_guest::amm));
    let pool = chain.instantiate(amm, (X, Y, FEE));
    chain.credit(ALICE, X, 600);
    chain.credit(pool, X, 1_000);
    chain.credit(pool, Y, u128::MAX);

    chain
        .transact(ALICE, |b| {
            let signed_in = account::authorize(b, ALICE)?;
            let funds = account::withdraw(b, signed_in, X, 500)?;
            let bought = b.call(pool, "swap", (funds, 0u128))?.one()?;
            account::deposit(b, ALICE, bought)
        })
        .expect_completed();

    // 30 bps on 500 leaves 498 effective, and `u128::MAX * 498 / 1498`
    // is a number the old expression could not reach at all.
    const OUT: u128 = 113_124_578_589_203_841_658_718_661_215_634_558_948;
    assert_eq!(chain.balance(ALICE, Y), OUT);
    assert_eq!(chain.balance(pool, Y), u128::MAX - OUT);
    assert_eq!(chain.balance(pool, X), 1_500);
}
