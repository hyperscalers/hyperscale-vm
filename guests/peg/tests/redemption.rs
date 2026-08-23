//! The window's own tests, against the real kernel.

use hyperscale_vm_sdk::state::{Fixed, Sign, SignedFixed, UnitFixed, Wide};
use hyperscale_vm_testing::{
    Chain, PrincipalAddr, ResourceAddr, account, package, principal, resource,
};
use peg_guest::peg::client::{Peg, Terms};
use peg_guest::peg::{Reserve, Stable};

const HOLDER: PrincipalAddr = principal(1);
const ORACLE: PrincipalAddr = principal(2);
const STABLE: ResourceAddr = resource(0x51);
const RESERVE: ResourceAddr = resource(0x52);

/// The stored rate's scale.
const ONE: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// A deviation of `scaled` at the stored scale, pointing `way`.
fn deviation(scaled: u128, way: Sign) -> SignedFixed<Reserve, Stable> {
    Fixed::from_scaled(Wide::from_u128(scaled))
        .signed(way)
        .expect("a deviation well inside the range")
}

/// A window quoting within a tenth of parity, funded to pay out.
fn window(mut chain: Chain) -> (Chain, Peg) {
    chain.publish(package!(peg_guest::peg));
    let window = chain.instantiate::<Peg>(
        HOLDER,
        Terms {
            stable: STABLE,
            reserve: RESERVE,
            oracle: ORACLE.into(),
            band: UnitFixed::percent(10).expect("a tenth is under one"),
        },
    );
    chain.credit(HOLDER, STABLE, 10_000);
    chain.credit(window, RESERVE, 10_000);
    (chain, window)
}

fn post(chain: &mut Chain, window: Peg, scaled: u128, way: Sign) {
    chain
        .transact(ORACLE, |b| {
            let signed_in = account::authorize(b, ORACLE)?;
            window.post_deviation(b, signed_in, deviation(scaled, way))
        })
        .expect_completed();
}

fn redeem(chain: &mut Chain, window: Peg, amount: u128) {
    chain
        .transact(HOLDER, |b| {
            let signed_in = account::authorize(b, HOLDER)?;
            let funds = account::withdraw(b, signed_in, STABLE, amount)?;
            let back = window.redeem(b, funds)?;
            account::deposit(b, HOLDER, back)
        })
        .expect_completed();
}

/// An unwritten deviation is parity, so a window nobody has priced
/// redeems one for one.
///
/// The value a cell reads as before anything writes it is the value zero,
/// and zero is the price this market starts at rather than a state its
/// bodies have to special-case.
#[hyperscale_vm_testing::test]
fn an_unpriced_window_redeems_at_parity(chain: Chain) {
    let (mut chain, window) = window(chain);
    redeem(&mut chain, window, 1_000);

    assert_eq!(chain.balance(HOLDER, RESERVE), 1_000);
    assert_eq!(chain.balance(window, STABLE), 1_000);
    assert_eq!(chain.balance(window, RESERVE), 9_000);
}

/// Above parity the redeemer takes more than they handed in.
///
/// Five percent over on a thousand is fifty of reserve on top.
#[hyperscale_vm_testing::test]
fn a_stable_above_parity_redeems_for_more(chain: Chain) {
    let (mut chain, window) = window(chain);
    post(&mut chain, window, ONE / 20, Sign::Positive);
    redeem(&mut chain, window, 1_000);

    assert_eq!(chain.balance(HOLDER, RESERVE), 1_050);
}

/// And below parity, for less — which is the same sentence with the sign
/// turned round, and the whole reason one cell holds both.
#[hyperscale_vm_testing::test]
fn a_stable_below_parity_redeems_for_less(chain: Chain) {
    let (mut chain, window) = window(chain);
    post(&mut chain, window, ONE / 20, Sign::Negative);
    redeem(&mut chain, window, 1_000);

    assert_eq!(chain.balance(HOLDER, RESERVE), 950);
}

/// The window keeps the subunit either way, which takes two roundings to
/// say once.
///
/// A third of a percent on 1,000 is 3.33 of reserve. Above parity the
/// redeemer takes 1,003 — the gain floored — and below it 996, the loss
/// raised. The window is up a subunit on both, which is what "down for
/// the redeemer" means at each end, and it is not one rounding said
/// twice.
#[hyperscale_vm_testing::test]
fn the_window_keeps_the_subunit_at_either_end(chain: Chain) {
    let third_of_a_percent = ONE / 300;
    let (mut chain, window) = window(chain);
    let taken = |chain: &Chain, before: u128| chain.balance(HOLDER, RESERVE) - before;

    post(&mut chain, window, third_of_a_percent, Sign::Positive);
    let before = chain.balance(HOLDER, RESERVE);
    redeem(&mut chain, window, 1_000);
    assert_eq!(taken(&chain, before), 1_003, "the gain is floored");

    post(&mut chain, window, third_of_a_percent, Sign::Negative);
    let before = chain.balance(HOLDER, RESERVE);
    redeem(&mut chain, window, 1_000);
    assert_eq!(taken(&chain, before), 996, "and the loss is not");
}

/// A market that has moved past the band is one the window declines to
/// quote in, whichever way it moved.
///
/// Both directions against one window, because the deviation is set
/// rather than accumulated: the second post is the whole of what the
/// market knows by the time the second redemption reads it.
#[hyperscale_vm_testing::test]
fn a_deviation_outside_the_band_is_refused(chain: Chain) {
    let (mut chain, window) = window(chain);
    let try_redeem = |chain: &mut Chain| {
        chain.transact(HOLDER, |b| {
            let signed_in = account::authorize(b, HOLDER)?;
            let funds = account::withdraw(b, signed_in, STABLE, 1_000)?;
            let back = window.redeem(b, funds)?;
            account::deposit(b, HOLDER, back)
        })
    };

    post(&mut chain, window, ONE / 5, Sign::Positive);
    assert_eq!(try_redeem(&mut chain).declined_as(), Some("outside-band"));

    post(&mut chain, window, ONE / 5, Sign::Negative);
    assert_eq!(try_redeem(&mut chain).declined_as(), Some("outside-band"));

    assert_eq!(
        chain.balance(HOLDER, STABLE),
        10_000,
        "a decline moves nothing"
    );
}

/// Only the configured oracle may say what the stable is trading at.
#[hyperscale_vm_testing::test]
fn only_the_oracle_may_post_a_deviation(chain: Chain) {
    let (mut chain, window) = window(chain);

    let outcome = chain.transact(HOLDER, |b| {
        let signed_in = account::authorize(b, HOLDER)?;
        window.post_deviation(b, signed_in, deviation(ONE / 20, Sign::Positive))
    });

    assert!(!outcome.completed(), "a price nobody may post does not land");
}

/// A quote is what a redemption would pay, asked without sending
/// anything — and the two agree because one calculation answers both.
#[hyperscale_vm_testing::test]
fn a_quote_is_what_a_redemption_pays(chain: Chain) {
    let (mut chain, window) = window(chain);
    post(&mut chain, window, ONE / 20, Sign::Negative);

    let outcome = chain.transact(HOLDER, |b| window.quote(b, 1_000u128));
    outcome.expect_completed();
    assert_eq!(outcome.answer::<u128>(0), 950);

    redeem(&mut chain, window, 1_000);
    assert_eq!(chain.balance(HOLDER, RESERVE), 950, "and it was not a guess");
}
