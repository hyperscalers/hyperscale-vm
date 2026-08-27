//! Funding the pool and leaving it, against the real kernel.

use amm_guest::amm::Error;
use amm_guest::amm::client::{Amm, Settings};
use hyperscale_vm_sdk::state::UnitFixed;
use hyperscale_vm_testing::{
    Chain, PrincipalAddr, ResourceAddr, ResourceKind, account, package, principal, resource,
};

const ALICE: PrincipalAddr = principal(1);
const BOB: PrincipalAddr = principal(2);
const X: ResourceAddr = resource(0xE1);
const Y: ResourceAddr = resource(0xE2);

/// An unfunded pool, with both providers holding both sides.
fn pool(mut chain: Chain) -> (Chain, Amm) {
    chain.publish(package!(amm_guest::amm));
    let pool = chain.instantiate::<Amm>(
        ALICE,
        Settings {
            x: X,
            y: Y,
            fee: UnitFixed::bps(30).expect("thirty basis points is under one"),
        },
    );
    for who in [ALICE, BOB] {
        chain.credit(who, X, 10_000);
        chain.credit(who, Y, 10_000);
    }
    (chain, pool)
}

/// The claim the pool issues, which is what a provider walks away with.
///
/// Asked of the chain rather than derived here: a share's address folds
/// the rules the pool grants over it, and those are the declaration's to
/// state.
fn share(chain: &Chain, pool: Amm) -> ResourceAddr {
    chain.issues(pool, ResourceKind::Fungible, amm_guest::amm::SHARE)
}

/// Fund both sides and keep the claim.
fn add(chain: &mut Chain, pool: Amm, who: PrincipalAddr, dx: u128, dy: u128) {
    chain
        .transact(who, |b| {
            let x_side = account::withdraw(b, who, X, dx)?;
            let y_side = account::withdraw(b, who, Y, dy)?;
            let claim = pool.add_liquidity(b, x_side, y_side)?;
            account::deposit(b, who, claim)
        })
        .expect_completed();
}

/// The first provider prices the pool, because nothing else can.
///
/// The mint is the geometric mean of the two sides — 1000 and 4000 give
/// 2000, computed here rather than read off the body — and it is the one
/// mint that does not divide by a reserve that is not there yet.
#[hyperscale_vm_testing::test]
fn the_first_provider_mints_the_geometric_mean(chain: Chain) {
    let (mut chain, pool) = pool(chain);
    add(&mut chain, pool, ALICE, 1_000, 4_000);

    assert_eq!(chain.balance(pool, X), 1_000);
    assert_eq!(chain.balance(pool, Y), 4_000);
    assert_eq!(chain.balance(ALICE, share(&chain, pool)), 2_000);
}

/// A later provider is priced against the lesser of the two claims they
/// could argue for.
///
/// Bob funds 100 of a 1000 X reserve and 800 of a 4000 Y reserve: a
/// tenth of one side and a fifth of the other, against a supply of 2000.
/// The X side argues for 200 and the Y side for 400, and he is minted
/// 200 — so the 400 Y he over-funded by stays in the pool, where every
/// provider including him holds a claim on it. Paying him for the excess
/// would be paying him out of everyone else's stake.
#[hyperscale_vm_testing::test]
fn a_skewed_deposit_mints_against_the_lesser_side(chain: Chain) {
    let (mut chain, pool) = pool(chain);
    add(&mut chain, pool, ALICE, 1_000, 4_000);
    add(&mut chain, pool, BOB, 100, 800);

    assert_eq!(chain.balance(BOB, share(&chain, pool)), 200);
    assert_eq!(chain.balance(pool, X), 1_100);
    assert_eq!(
        chain.balance(pool, Y),
        4_800,
        "the excess stays in the pool"
    );
    assert_eq!(
        chain.balance(ALICE, share(&chain, pool)),
        2_000,
        "and dilutes nobody"
    );
}

/// Funding one side alone buys nothing, so it is refused rather than
/// taken.
///
/// The lesser claim is zero whatever the other side was worth, and a
/// provider who funds a pool and is minted nothing has made a donation
/// they never offered. The decline discards the whole transaction, so
/// the funds stay where they were.
#[hyperscale_vm_testing::test]
fn funding_one_side_alone_is_refused(chain: Chain) {
    let (mut chain, pool) = pool(chain);
    add(&mut chain, pool, ALICE, 1_000, 4_000);

    let outcome = chain.transact(BOB, |b| {
        let x_side = account::withdraw(b, BOB, X, 0)?;
        let y_side = account::withdraw(b, BOB, Y, 500)?;
        let claim = pool.add_liquidity(b, x_side, y_side)?;
        account::deposit(b, BOB, claim)
    });

    outcome.expect_declined(Error::NothingMinted);
    assert_eq!(chain.balance(BOB, Y), 10_000, "a decline moves nothing");
    assert_eq!(chain.balance(pool, Y), 4_000);
}

/// Redeeming the only position returns the whole pair.
///
/// One provider, no trades, so there is nothing for the rounding to keep
/// and the pool empties exactly.
#[hyperscale_vm_testing::test]
fn redeeming_the_only_position_returns_the_whole_pair(chain: Chain) {
    let (mut chain, pool) = pool(chain);
    add(&mut chain, pool, ALICE, 1_000, 4_000);

    let claim_on = share(&chain, pool);
    chain
        .transact(ALICE, |b| {
            let claim = account::withdraw(b, ALICE, claim_on, 2_000)?;
            let [back_x, back_y] = pool.remove_liquidity(b, claim)?;
            account::deposit(b, ALICE, back_x)?;
            account::deposit(b, ALICE, back_y)
        })
        .expect_completed();

    assert_eq!(chain.balance(pool, X), 0);
    assert_eq!(chain.balance(pool, Y), 0);
    assert_eq!(chain.balance(ALICE, X), 10_000);
    assert_eq!(chain.balance(ALICE, Y), 10_000);
    assert_eq!(
        chain.balance(ALICE, share(&chain, pool)),
        0,
        "the claim is burned"
    );
}
