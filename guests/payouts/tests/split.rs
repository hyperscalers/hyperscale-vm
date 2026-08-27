//! The splitter's own tests, against the real kernel.

use hyperscale_vm_sdk::state::UnitFixed;
use hyperscale_vm_testing::{
    Chain, PrincipalAddr, ResourceAddr, Worlds, account, package, principal, resource,
};
use payouts_guest::payouts::Error;
use payouts_guest::payouts::client::{Payouts, Terms};

const PAYER: PrincipalAddr = principal(1);
const PROTOCOL: PrincipalAddr = principal(2);
const TREASURY: PrincipalAddr = principal(3);
const REFERRER: PrincipalAddr = principal(4);
const ASSET: ResourceAddr = resource(0xA1);

/// A splitter at a quarter, a quarter and a half — a table that claims
/// the whole, so what is left over is only ever the truncated subunit.
fn splitter(chain: &mut Chain) -> Payouts {
    static WORLDS: Worlds<Payouts> = Worlds::new();
    WORLDS.open(chain, |chain| {
        chain.publish(package!(payouts_guest::payouts));
        let splitter = chain.instantiate::<Payouts>(
            PAYER,
            Terms {
                asset: ASSET,
                protocol: UnitFixed::percent(25).expect("a quarter is under one"),
                treasury: UnitFixed::percent(25).expect("a quarter is under one"),
                referrer: UnitFixed::percent(50).expect("a half is under one"),
            },
        );
        chain.credit(PAYER, ASSET, 10_000);
        splitter
    })
}

/// A payment the table divides exactly pays every share and leaves
/// nothing behind.
#[hyperscale_vm_testing::test]
fn a_payment_that_divides_pays_every_share(chain: &mut Chain) {
    let splitter = splitter(chain);

    chain
        .transact(PAYER, |b| {
            let pot = account::withdraw(b, PAYER, ASSET, 100)?;
            let [protocol, treasury, referrer] = splitter.disburse(b, pot)?;
            account::deposit(b, PROTOCOL, protocol)?;
            account::deposit(b, TREASURY, treasury)?;
            account::deposit(b, REFERRER, referrer)
        })
        .expect_completed();

    assert_eq!(chain.balance(PROTOCOL, ASSET), 25);
    assert_eq!(chain.balance(TREASURY, ASSET), 25);
    assert_eq!(chain.balance(REFERRER, ASSET), 50);
    assert_eq!(chain.balance(splitter, ASSET), 0, "nothing was left over");
}

/// A payment the table cannot divide pays every share of the whole and
/// the splitter keeps what none of them claimed.
///
/// 101 at a quarter, a quarter and a half is 25, 25 and 50: every share
/// is floored against the payment itself rather than against what the
/// share before it left, so the subunit that will not divide is one
/// subunit and not three.
#[hyperscale_vm_testing::test]
fn a_payment_that_does_not_divide_keeps_the_dust(chain: &mut Chain) {
    let splitter = splitter(chain);

    chain
        .transact(PAYER, |b| {
            let pot = account::withdraw(b, PAYER, ASSET, 101)?;
            let [protocol, treasury, referrer] = splitter.disburse(b, pot)?;
            account::deposit(b, PROTOCOL, protocol)?;
            account::deposit(b, TREASURY, treasury)?;
            account::deposit(b, REFERRER, referrer)
        })
        .expect_completed();

    assert_eq!(chain.balance(PROTOCOL, ASSET), 25);
    assert_eq!(chain.balance(TREASURY, ASSET), 25);
    assert_eq!(chain.balance(REFERRER, ASSET), 50);
    assert_eq!(chain.balance(splitter, ASSET), 1, "the dust stays put");
}

/// A schedule that has to add up settles when it does.
#[hyperscale_vm_testing::test]
fn a_schedule_that_adds_up_settles(chain: &mut Chain) {
    let splitter = splitter(chain);

    chain
        .transact(PAYER, |b| {
            let pot = account::withdraw(b, PAYER, ASSET, 100)?;
            let [protocol, treasury, referrer] = splitter.settle(b, pot)?;
            account::deposit(b, PROTOCOL, protocol)?;
            account::deposit(b, TREASURY, treasury)?;
            account::deposit(b, REFERRER, referrer)
        })
        .expect_completed();

    assert_eq!(chain.balance(PROTOCOL, ASSET), 25);
    assert_eq!(chain.balance(REFERRER, ASSET), 50);
}

/// And refuses when it does not, rather than paying out parts that do
/// not sum to what arrived.
#[hyperscale_vm_testing::test]
fn a_schedule_that_must_add_up_refuses_the_dust(chain: &mut Chain) {
    let splitter = splitter(chain);

    let outcome = chain.transact(PAYER, |b| {
        let pot = account::withdraw(b, PAYER, ASSET, 101)?;
        let [protocol, treasury, referrer] = splitter.settle(b, pot)?;
        account::deposit(b, PROTOCOL, protocol)?;
        account::deposit(b, TREASURY, treasury)?;
        account::deposit(b, REFERRER, referrer)
    });

    outcome.expect_declined(Error::ShareUnclaimed);
    assert_eq!(
        chain.balance(PAYER, ASSET),
        10_000,
        "a decline moves nothing"
    );
    assert_eq!(chain.balance(PROTOCOL, ASSET), 0);
    assert_eq!(chain.balance(splitter, ASSET), 0);
}

/// A payment is rounded down to whole lots and the change goes back.
#[hyperscale_vm_testing::test]
fn a_payment_is_rounded_down_to_whole_lots(chain: &mut Chain) {
    let splitter = splitter(chain);

    chain
        .transact(PAYER, |b| {
            let pot = account::withdraw(b, PAYER, ASSET, 950)?;
            let [payable, change] = splitter.in_lots(b, pot, 100u128)?;
            account::deposit(b, TREASURY, payable)?;
            account::deposit(b, PAYER, change)
        })
        .expect_completed();

    assert_eq!(chain.balance(TREASURY, ASSET), 900);
    assert_eq!(chain.balance(PAYER, ASSET), 10_000 - 900);
}

/// A payment short of a single lot is refused rather than rounded to
/// nothing.
#[hyperscale_vm_testing::test]
fn a_payment_short_of_one_lot_is_refused(chain: &mut Chain) {
    let splitter = splitter(chain);

    let outcome = chain.transact(PAYER, |b| {
        let pot = account::withdraw(b, PAYER, ASSET, 50)?;
        let [payable, change] = splitter.in_lots(b, pot, 100u128)?;
        account::deposit(b, TREASURY, payable)?;
        account::deposit(b, PAYER, change)
    });

    outcome.expect_declined(Error::BelowOneLot);
    assert_eq!(chain.balance(PAYER, ASSET), 10_000);
}

/// A lot of nothing is not a lot.
///
/// Rounding to a multiple of zero is the identity, so a caller naming one
/// would be paid in full by the method whose whole job is to round — and
/// `divides` already answers no to a zero step. The two agree.
#[hyperscale_vm_testing::test]
fn a_lot_of_nothing_is_refused(chain: &mut Chain) {
    let splitter = splitter(chain);

    let outcome = chain.transact(PAYER, |b| {
        let pot = account::withdraw(b, PAYER, ASSET, 950)?;
        let [payable, change] = splitter.in_lots(b, pot, 0u128)?;
        account::deposit(b, TREASURY, payable)?;
        account::deposit(b, PAYER, change)
    });

    outcome.expect_declined(Error::BelowOneLot);
    assert_eq!(
        chain.balance(PAYER, ASSET),
        10_000,
        "a decline moves nothing"
    );
}
