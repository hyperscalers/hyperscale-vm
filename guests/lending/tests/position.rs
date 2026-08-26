//! The position's own tests, against the real kernel.

use hyperscale_vm_sdk::state::{Fixed, UnitFixed, Wide};
use hyperscale_vm_testing::{
    AdmissionError, Chain, PrincipalAddr, Refused, ResourceAddr, account, package, principal,
    resource,
};
use lending_guest::lending::client::{Lending, Terms};

const BORROWER: PrincipalAddr = principal(1);
const ORACLE: PrincipalAddr = principal(2);
const KEEPER: PrincipalAddr = principal(3);
const COLLATERAL: ResourceAddr = resource(0xC1);
const DEBT: ResourceAddr = resource(0xD1);

/// The stored rate's scale: one whole unit per unit.
const ONE: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// A hundredth of a percent per period, as the rate a slot holds.
fn growth() -> Fixed<lending_guest::lending::Share, lending_guest::lending::Share> {
    Fixed::from_scaled(Wide::from_u128(ONE + ONE / 10_000))
}

/// A market at half loan-to-value, liquidating past four fifths, funded
/// with debt to lend and a borrower holding collateral.
fn market(mut chain: Chain) -> (Chain, Lending) {
    chain.publish(package!(lending_guest::lending));
    let market = chain.instantiate::<Lending>(
        BORROWER,
        Terms {
            collateral: COLLATERAL,
            debt: DEBT,
            oracle: ORACLE.into(),
            ltv: UnitFixed::percent(50).expect("a half is under one"),
            liquidation_threshold: UnitFixed::percent(80).expect("four fifths is under one"),
            growth_per_period: growth(),
        },
    );
    chain.credit(BORROWER, COLLATERAL, 10_000);
    chain.credit(market, DEBT, 10_000);
    (chain, market)
}

/// A rate at `scaled`, which is what the slot the price lands in holds.
fn rate<A, B>(scaled: u128) -> Fixed<A, B> {
    Fixed::from_scaled(Wide::from_u128(scaled))
}

/// Post a price for each side: collateral at two, debt at one.
fn price(chain: &mut Chain, market: Lending, collateral: u128, debt: u128) {
    chain
        .transact(ORACLE, |b| {
            let signed_in = account::authorize(b, ORACLE)?;
            market.post_price(b, signed_in, rate(collateral), rate(debt))
        })
        .expect_completed();
}

/// Post collateral and draw against it, in one manifest with the accrual
/// the draw insists on.
fn open(chain: &mut Chain, market: Lending, posted: u128, drawn: u128, now: u64) {
    chain
        .transact(BORROWER, |b| {
            let signed_in = account::authorize(b, BORROWER)?;
            let funds = account::withdraw(b, signed_in, COLLATERAL, posted)?;
            market.deposit(b, funds)?;
            market.accrue(b, now)?;
            let drawn = market.draw(b, drawn, now)?;
            account::deposit(b, BORROWER, drawn)
        })
        .expect_completed();
}

/// A position posts collateral and draws debt against it.
#[hyperscale_vm_testing::test]
fn a_position_borrows_against_its_collateral(chain: Chain) {
    let (mut chain, market) = market(chain);
    price(&mut chain, market, 2 * ONE, ONE);
    open(&mut chain, market, 1_000, 500, 0);

    assert_eq!(chain.balance(market, COLLATERAL), 1_000);
    assert_eq!(chain.balance(BORROWER, DEBT), 500);
    assert_eq!(chain.balance(market, DEBT), 9_500);
}

/// A draw past what the collateral allows is refused.
///
/// A thousand of collateral at two is two thousand of backing, and half
/// of that is a thousand of debt at one. Eleven hundred is over.
#[hyperscale_vm_testing::test]
fn a_draw_past_the_ratio_is_refused(chain: Chain) {
    let (mut chain, market) = market(chain);
    price(&mut chain, market, 2 * ONE, ONE);

    let outcome = chain.transact(BORROWER, |b| {
        let signed_in = account::authorize(b, BORROWER)?;
        let funds = account::withdraw(b, signed_in, COLLATERAL, 1_000)?;
        market.deposit(b, funds)?;
        market.accrue(b, 0u64)?;
        let drawn = market.draw(b, 1_100u128, 0u64)?;
        account::deposit(b, BORROWER, drawn)
    });

    assert_eq!(outcome.declined_as(), Some("over-ltv"));
    assert_eq!(chain.balance(BORROWER, COLLATERAL), 10_000);
}

/// A draw against an index nobody carried is refused rather than priced
/// off a stale number.
#[hyperscale_vm_testing::test]
fn a_draw_against_a_stale_index_is_refused(chain: Chain) {
    let (mut chain, market) = market(chain);
    price(&mut chain, market, 2 * ONE, ONE);

    let outcome = chain.transact(BORROWER, |b| {
        let signed_in = account::authorize(b, BORROWER)?;
        let funds = account::withdraw(b, signed_in, COLLATERAL, 1_000)?;
        market.deposit(b, funds)?;
        let drawn = market.draw(b, 100u128, 7u64)?;
        account::deposit(b, BORROWER, drawn)
    });

    assert_eq!(outcome.declined_as(), Some("index-stale"));
}

/// Only the configured oracle may say what the sides are worth.
///
/// Refused before the transaction exists: the gate is a rule over a
/// configuration slot, so what satisfies it is a pure match over what the
/// signed form presents, and no state is read to answer. A keeper who is
/// not the oracle pays nothing to find out — which is also why it is not
/// a decline: a decline is a body's own verdict, and no body ran.
#[hyperscale_vm_testing::test]
fn only_the_oracle_may_post_a_price(chain: Chain) {
    let (mut chain, market) = market(chain);

    let refused = chain
        .try_transact(KEEPER, |b| {
            let signed_in = account::authorize(b, KEEPER)?;
            market.post_price(b, signed_in, rate(ONE), rate(ONE))
        })
        .err();

    assert!(
        matches!(
            refused,
            Some(Refused::Admission(AdmissionError::EvidenceUnsatisfied { .. }))
        ),
        "a price nobody may post is not a transaction: {refused:?}"
    );
}

/// A covered position is not liquidatable, however much a keeper wants
/// it to be.
#[hyperscale_vm_testing::test]
fn a_covered_position_cannot_be_liquidated(chain: Chain) {
    let (mut chain, market) = market(chain);
    price(&mut chain, market, 2 * ONE, ONE);
    open(&mut chain, market, 1_000, 500, 0);

    let outcome = chain.transact(KEEPER, |b| {
        market.accrue(b, 0u64)?;
        let seized = market.liquidate(b, 0u64)?;
        account::deposit(b, KEEPER, seized)
    });

    assert_eq!(outcome.declined_as(), Some("still-covered"));
    assert_eq!(chain.balance(market, COLLATERAL), 1_000);
}

/// A fall in what the collateral is worth is what makes a position
/// liquidatable, and the keeper takes the collateral.
///
/// Five hundred of debt against a thousand of collateral: at a price of
/// two the position owes a quarter of what it posted, and at a price of
/// a half it owes it all — past the four fifths the market liquidates
/// at.
#[hyperscale_vm_testing::test]
fn a_price_fall_makes_a_position_liquidatable(chain: Chain) {
    let (mut chain, market) = market(chain);
    price(&mut chain, market, 2 * ONE, ONE);
    open(&mut chain, market, 1_000, 500, 0);
    price(&mut chain, market, ONE / 2, ONE);

    chain
        .transact(KEEPER, |b| {
            market.accrue(b, 0u64)?;
            let seized = market.liquidate(b, 0u64)?;
            account::deposit(b, KEEPER, seized)
        })
        .expect_completed();

    assert_eq!(chain.balance(KEEPER, COLLATERAL), 1_000);
    assert_eq!(chain.balance(market, COLLATERAL), 0);
}

/// The index carries the whole span in one exponentiation.
///
/// A hundredth of a percent per period, twice, is `1.0001^2` exactly —
/// `1.00020001` — and the scale holds every digit of it. Computed here
/// rather than read off the body.
///
/// The first accrual anchors and the second carries: a market nobody has
/// accrued has not been anywhere, so there is no span from before it to
/// compound across. Every borrowing path composes an accrual anyway, so
/// the anchor costs a caller nothing it was not already writing.
#[hyperscale_vm_testing::test]
fn the_index_compounds_over_the_span_it_carries(chain: Chain) {
    let (mut chain, market) = market(chain);

    let outcome = chain.transact(BORROWER, |b| {
        market.accrue(b, 0u64)?;
        market.accrue(b, 2u64)?;
        market.index_scaled(b)
    });
    outcome.expect_completed();

    const TWICE: u128 = 1_000_200_010_000_000_000_000_000_000_000_000_000;
    assert_eq!(outcome.answer(), Some(TWICE));
}

/// Carrying the index a step at a time is not the same number as
/// carrying it in one span.
///
/// Each carry quantizes once and rounds down, so a hundred carries throw
/// away a hundred subunits of the stored rate where one span throws away
/// only what its squaring costs. Short spans hide this — through ten
/// periods the two agree to the digit, because `1.0001^k` is exactly
/// representable at this scale until `k` passes nine — and a hundred
/// periods separate them.
///
/// The direction is the part that matters and it does not vary: the
/// market never charges *more* because somebody accrued it often. The
/// index is a function of how it was reached and not only of the span it
/// covers, which is a property to pin rather than to discover.
#[hyperscale_vm_testing::test]
fn carrying_the_index_step_by_step_is_not_carrying_it_once(chain: Chain) {
    let (mut chain, stepwise) = market(chain);

    let outcome = chain.transact(BORROWER, |b| {
        stepwise.accrue(b, 0u64)?;
        for period in 1..=100u64 {
            stepwise.accrue(b, period)?;
        }
        stepwise.index_scaled(b)
    });
    outcome.expect_completed();
    let stepped = outcome.answer().expect("an index this size fits");

    let (mut chain, oneshot) = market(chain);
    let outcome = chain.transact(BORROWER, |b| {
        oneshot.accrue(b, 0u64)?;
        oneshot.accrue(b, 100u64)?;
        oneshot.index_scaled(b)
    });
    outcome.expect_completed();
    let once = outcome.answer().expect("an index this size fits");

    assert!(
        stepped <= once,
        "rounding down cannot make the debt grow faster"
    );
    assert_ne!(stepped, once, "and a hundred roundings are not one");
}

/// A market nobody has accrued anchors to the period it is handed, rather
/// than compounding across every period before it.
///
/// The clock a real caller passes is a timestamp, and raising the growth
/// to one is an exponent nothing survives. What makes that expressible is
/// that the cell holds *nothing* until somebody writes it — a bare number
/// would have had to spend a period to say so, and period zero is one this
/// market's borrowers use.
#[hyperscale_vm_testing::test]
fn a_market_nobody_accrued_anchors_rather_than_compounding(chain: Chain) {
    let (mut chain, market) = market(chain);

    let outcome = chain.transact(BORROWER, |b| {
        market.accrue(b, 1_750_000_000_000u64)?;
        market.index_scaled(b)
    });
    outcome.expect_completed();

    assert_eq!(outcome.answer(), Some(ONE), "the index is where it started");
}

/// A position whose collateral is worth nothing is liquidatable, which
/// is the most exceeded a threshold ever gets.
///
/// It used to be refused, and refused as `nothing-owed`: the ratio of
/// exposure to backing needs a denominator, and backing that rounds away
/// has none. Comparing rather than dividing is what gives the case its
/// answer instead of its refusal.
///
/// Reached by a price that falls rather than by one that is unset — a
/// thousand of collateral at a two-thousandth is worth half a subunit,
/// which floors to nothing while still being a price somebody posted.
#[hyperscale_vm_testing::test]
fn a_position_whose_backing_rounds_away_is_liquidatable(chain: Chain) {
    let (mut chain, market) = market(chain);
    price(&mut chain, market, 2 * ONE, ONE);
    open(&mut chain, market, 1_000, 500, 0);
    price(&mut chain, market, ONE / 2_000, ONE);

    chain
        .transact(KEEPER, |b| {
            market.accrue(b, 0u64)?;
            let seized = market.liquidate(b, 0u64)?;
            account::deposit(b, KEEPER, seized)
        })
        .expect_completed();

    assert_eq!(chain.balance(KEEPER, COLLATERAL), 1_000);
    assert_eq!(chain.balance(market, COLLATERAL), 0);
}
