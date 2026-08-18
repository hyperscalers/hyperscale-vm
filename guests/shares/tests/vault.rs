//! The share vault's own tests, against the real kernel.

use hyperscale_vm_testing::{
    Chain, PrincipalAddr, ResourceAddr, account, package, principal, resource,
};
use shares_guest::shares::client::{Settings, Shares};

const ALICE: PrincipalAddr = principal(1);
const MALLORY: PrincipalAddr = principal(2);
const ASSET: ResourceAddr = resource(0xA1);

/// An empty vault, with Alice and Mallory each holding assets.
fn vault() -> (Chain, Shares) {
    let mut chain = Chain::native();
    chain.publish(package!(shares_guest::shares));
    let vault = chain.instantiate::<Shares>(Settings {
        asset: ASSET.address(),
    });
    chain.credit(ALICE, ASSET, 10_000);
    chain.credit(MALLORY, ASSET, 10_000);
    (chain, vault)
}

/// Deposit `amount` for `who`, keeping the shares in their account.
fn deposit(chain: &mut Chain, vault: Shares, who: PrincipalAddr, amount: u128) {
    chain
        .transact(who, |b| {
            let signed_in = account::authorize(b, who)?;
            let funds = account::withdraw(b, signed_in, ASSET, amount)?;
            let shares = vault.deposit(b, funds)?;
            account::deposit(b, who, shares)
        })
        .expect_completed();
}

/// The first depositor prices a share at par, because nothing else can be
/// priced against an empty pool.
#[test]
fn the_first_deposit_mints_at_par() {
    let (mut chain, vault) = vault();
    deposit(&mut chain, vault, ALICE, 1_000);
    assert_eq!(chain.balance(vault, ASSET), 1_000);
}

/// A second depositor into an unchanged pool gets the same rate, and the
/// pool holds both stakes.
#[test]
fn a_later_deposit_prices_against_the_pool() {
    let (mut chain, vault) = vault();
    deposit(&mut chain, vault, ALICE, 1_000);
    deposit(&mut chain, vault, MALLORY, 500);
    assert_eq!(chain.balance(vault, ASSET), 1_500);
}

/// Round-tripping the whole position returns the whole stake: with one
/// holder and no growth, redeeming every share is redeeming everything.
#[test]
fn redeeming_every_share_returns_every_asset() {
    let (mut chain, vault) = vault();
    deposit(&mut chain, vault, ALICE, 1_000);

    chain
        .transact(ALICE, |b| {
            let signed_in = account::authorize(b, ALICE)?;
            let units = account::withdraw(b, signed_in, Chain::issued(vault, b""), 1_000)?;
            let back = vault.redeem(b, units)?;
            account::deposit(b, ALICE, back)
        })
        .expect_completed();

    assert_eq!(chain.balance(vault, ASSET), 0);
    assert_eq!(chain.balance(ALICE, ASSET), 10_000);
}

/// The inflation attack, stated as what actually defends against it.
///
/// The classic version is: be the first depositor for one subunit, donate
/// a fortune to the pool, and the next depositor's mint rounds to nothing
/// while you hold every share. Rounding direction does not stop it —
/// rounding toward the vault favours existing shareholders, and here the
/// existing shareholder is the attacker.
///
/// What stops it is that the donation has nowhere to happen. Assets reach
/// this instance only through a body that takes a bucket, and every such
/// body mints against what arrived. Mallory's "donation" is a deposit, so
/// it buys shares, so it is not a donation — and Alice's stake is
/// unharmed.
#[test]
fn there_is_no_path_that_grows_assets_without_minting_shares() {
    let (mut chain, vault) = vault();

    // Mallory takes the first position, as small as one gets.
    deposit(&mut chain, vault, MALLORY, 1);

    // And tries to inflate the share price. The only way in is `deposit`,
    // which mints against it.
    deposit(&mut chain, vault, MALLORY, 9_000);

    // Alice deposits after the "donation" and mints a real position
    // rather than rounding to nothing.
    deposit(&mut chain, vault, ALICE, 1_000);

    // She can redeem it for substantially what she put in. The subunit
    // the pool keeps on the way in and on the way out is the whole of
    // what she loses.
    chain
        .transact(ALICE, |b| {
            let signed_in = account::authorize(b, ALICE)?;
            let units = account::withdraw(b, signed_in, Chain::issued(vault, b""), 1_000)?;
            let back = vault.redeem(b, units)?;
            account::deposit(b, ALICE, back)
        })
        .expect_completed();

    assert!(
        chain.balance(ALICE, ASSET) >= 9_998,
        "a deposit after a would-be donation is still worth what it cost, \
         less the subunits the pool keeps in each direction: {}",
        chain.balance(ALICE, ASSET)
    );
}

