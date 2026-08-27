//! The position's own tests, against the real kernel.

use hyperscale_vm_sdk::state::{Fixed, UnitFixed, Wide};
use hyperscale_vm_testing::{
    Chain, PrincipalAddr, Refused, ResourceAddr, TypedError, Worlds, account, package, principal,
    resource,
};
use perp_guest::perp::Error;
use perp_guest::perp::client::{Perp, Terms};

const TRADER: PrincipalAddr = principal(1);
const ORACLE: PrincipalAddr = principal(2);
const KEEPER: PrincipalAddr = principal(3);
const COLLATERAL: ResourceAddr = resource(0xC1);

/// The stored rate's scale.
const ONE: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// A market holding one position on the named side, at a tenth
/// maintenance and a fifth liquidation bonus.
///
/// A world per side: the side is creation-fixed, so a long market and a
/// short one are two instances rather than one reconfigured.
fn market(chain: Chain, long: bool) -> (Chain, Perp) {
    static LONGS: Worlds<Perp> = Worlds::new();
    static SHORTS: Worlds<Perp> = Worlds::new();
    let worlds = if long { &LONGS } else { &SHORTS };
    worlds.open(chain, |chain| {
        chain.publish(package!(perp_guest::perp));
        let market = chain.instantiate::<Perp>(
            TRADER,
            Terms {
                collateral: COLLATERAL,
                oracle: ORACLE.into(),
                maintenance_margin: UnitFixed::percent(10).expect("a tenth is under one"),
                liquidation_bonus: UnitFixed::percent(20).expect("a fifth is under one"),
                long,
            },
        );
        chain.credit(TRADER, COLLATERAL, 10_000);
        chain.credit(market, COLLATERAL, 10_000);
        market
    })
}

/// A rate at `scaled`, which is what the cell the mark lands in holds.
fn rate<A, B>(scaled: u128) -> Fixed<A, B> {
    Fixed::from_scaled(Wide::from_u128(scaled))
}

fn mark(chain: &mut Chain, market: Perp, scaled: u128) {
    chain
        .transact(ORACLE, |b| market.post_mark(b, rate(scaled)))
        .expect_completed();
}

fn open(chain: &mut Chain, market: Perp, margin: u128, size: u128) {
    chain
        .transact(TRADER, |b| {
            let funds = account::withdraw(b, TRADER, COLLATERAL, margin)?;
            market.open(b, funds, size)
        })
        .expect_completed();
}

fn close(chain: &mut Chain, market: Perp) {
    chain
        .transact(TRADER, |b| {
            let back = market.close(b)?;
            account::deposit(b, TRADER, back)
        })
        .expect_completed();
}

/// A long that closes where it opened gets its margin back.
#[hyperscale_vm_testing::test]
fn a_position_closed_at_its_entry_returns_the_margin(chain: Chain) {
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 1_000, 100);
    close(&mut chain, market);

    assert_eq!(chain.balance(TRADER, COLLATERAL), 10_000);
}

/// A long profits when the mark rises: a hundred base from two to three
/// is a hundred of quote.
#[hyperscale_vm_testing::test]
fn a_long_gains_what_the_mark_rose(chain: Chain) {
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 1_000, 100);
    mark(&mut chain, market, 3 * ONE);
    close(&mut chain, market);

    assert_eq!(chain.balance(TRADER, COLLATERAL), 10_100);
}

/// And the same move is the short's loss, which is the same sentence the
/// other way round.
#[hyperscale_vm_testing::test]
fn a_short_loses_what_the_mark_rose(chain: Chain) {
    let (mut chain, market) = market(chain, false);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 1_000, 100);
    mark(&mut chain, market, 3 * ONE);
    close(&mut chain, market);

    assert_eq!(chain.balance(TRADER, COLLATERAL), 9_900);
}

/// Funding travels both ways, and what a position owes is the distance
/// the cumulative figure moved while it was open.
///
/// Charged a tenth of a quote per base, then credited three tenths: the
/// figure ends at two tenths the other way, so a long that paid at first
/// is net paid twenty of quote on a hundred base.
#[hyperscale_vm_testing::test]
fn funding_that_flips_sign_settles_the_net(chain: Chain) {
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 1_000, 100);

    chain
        .transact(ORACLE, |b| {
            market.charge_longs(b, rate(ONE / 10))?;
            market.credit_longs(b, rate(3 * ONE / 10))
        })
        .expect_completed();
    close(&mut chain, market);

    assert_eq!(chain.balance(TRADER, COLLATERAL), 10_020);
}

/// Only the oracle may mark the market.
///
/// Refused before the transaction exists: the gate is a rule over a
/// configuration slot, and the builder reads the same declaration
/// admission judges — so a keeper who is not the oracle is refused at
/// the compose site, before anything is signed.
#[hyperscale_vm_testing::test]
fn only_the_oracle_may_mark(chain: Chain) {
    let (mut chain, market) = market(chain, true);

    let refused = chain
        .try_transact(KEEPER, |b| {
            market.post_mark(
                b,
                rate::<perp_guest::perp::Quote, perp_guest::perp::Base>(ONE),
            )
        })
        .err();

    assert!(
        matches!(
            refused,
            Some(Refused::Typed(TypedError::SignatureForGuarded { .. }))
        ),
        "a mark nobody may post is not a transaction: {refused:?}"
    );
}

/// A position whose equity falls under the maintenance requirement is
/// seized, and the liquidator takes its cut.
///
/// A hundred base opened at two on a thousand of margin: at a mark of
/// eleven tenths the long has lost ninety, leaving ten against a
/// maintenance requirement of eleven.
#[hyperscale_vm_testing::test]
fn a_position_under_maintenance_is_liquidated(chain: Chain) {
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 100, 100);
    mark(&mut chain, market, 11 * ONE / 10);

    chain
        .transact(KEEPER, |b| {
            let seized = market.liquidate(b)?;
            account::deposit(b, KEEPER, seized)
        })
        .expect_completed();

    assert_eq!(
        chain.balance(KEEPER, COLLATERAL),
        2,
        "a fifth of the ten left"
    );
}

/// A covered position is not seizable.
#[hyperscale_vm_testing::test]
fn a_covered_position_is_not_liquidated(chain: Chain) {
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 1_000, 100);

    let outcome = chain.transact(KEEPER, |b| {
        let seized = market.liquidate(b)?;
        account::deposit(b, KEEPER, seized)
    });

    outcome.expect_declined(Error::StillCovered);
}

/// A position of no size is not a position, and the margin beside it does
/// not vanish into the market.
///
/// The bug this refusal names: openness used to be read off the size, so
/// a size of zero opened nothing, banked the margin, and left `close`
/// declining against a market that held it.
#[hyperscale_vm_testing::test]
fn a_position_of_no_size_is_refused(chain: Chain) {
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);

    let outcome = chain.transact(TRADER, |b| {
        let funds = account::withdraw(b, TRADER, COLLATERAL, 1_000)?;
        market.open(b, funds, 0u128)
    });

    outcome.expect_declined(Error::EmptyPosition);
    assert_eq!(
        chain.balance(TRADER, COLLATERAL),
        10_000,
        "nothing is banked"
    );
}

/// A market already holding a position refuses a second one before the
/// transaction exists.
///
/// The record's leaf has to be absent for `open` to run, so this is the
/// declaration's refusal rather than a check the body performs — which is
/// why it reads as a refusal and not as a decline.
#[hyperscale_vm_testing::test]
fn a_market_holding_a_position_takes_no_other(chain: Chain) {
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 1_000, 100);

    let outcome = chain.transact(TRADER, |b| {
        let funds = account::withdraw(b, TRADER, COLLATERAL, 1_000)?;
        market.open(b, funds, 100u128)
    });

    assert!(
        outcome.declined_as().is_none(),
        "an unmet presence is not a decline"
    );
    assert!(!outcome.completed());
}

/// And a market that closed one takes the next.
///
/// What `retire` buys: presence can say a thing stopped being true, so
/// the same market opens again rather than being a one-way door.
#[hyperscale_vm_testing::test]
fn a_closed_market_opens_again(chain: Chain) {
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 1_000, 100);
    close(&mut chain, market);
    open(&mut chain, market, 1_000, 100);
    close(&mut chain, market);

    assert_eq!(chain.balance(TRADER, COLLATERAL), 10_000);
}

/// What a position pays rounds up and what it is paid rounds down, which
/// a single netted figure could not say.
///
/// A third of a subunit per base, charged and credited alike, on a
/// hundred base: the position owes 34 and is owed 33, so it settles a
/// subunit down on a wash. Netting first would have made both zero.
#[hyperscale_vm_testing::test]
fn the_two_directions_of_funding_round_apart(chain: Chain) {
    let a_third = ONE / 3;
    let (mut chain, market) = market(chain, true);
    mark(&mut chain, market, 2 * ONE);
    open(&mut chain, market, 1_000, 100);

    chain
        .transact(ORACLE, |b| {
            market.charge_longs(b, rate(a_third))?;
            market.credit_longs(b, rate(a_third))
        })
        .expect_completed();
    close(&mut chain, market);

    assert_eq!(
        chain.balance(TRADER, COLLATERAL),
        9_999,
        "the market keeps the subunit at both ends"
    );
}
