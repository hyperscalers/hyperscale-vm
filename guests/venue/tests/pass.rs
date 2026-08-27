//! The pass: a proof paid for, declined short, and spent downstream.
//!
//! One transaction carries all three calls — pay, prove, enter — so
//! what these pin is atomicity doing the invariant's work: a short
//! payment declines the prover, the decline fails the transaction
//! wholesale, and the gated call never ran. A proof without a payment
//! is not a composition anybody can spell, because the payment is the
//! proving method's own parameter.

use hyperscale_vm_testing::{
    Chain, Component, PrincipalAddr, ResourceAddr, Worlds, account, package, principal, resource,
};
use venue_guest::venue;

const ALICE: PrincipalAddr = principal(0xA1);
const XRD: ResourceAddr = resource(0xE1);
/// What the door charges, in subunits of its configured asset.
const PRICE: u128 = 10;

/// A door selling passes at [`PRICE`], the hall its pass admits into,
/// and Alice holding a hundred.
fn world(chain: &mut Chain) -> (venue::client::Venue, venue::client::Venue) {
    static WORLDS: Worlds<(venue::client::Venue, venue::client::Venue)> = Worlds::new();
    WORLDS.open(chain, |chain| {
        chain.publish(package!(venue_guest::venue));
        let door = chain.instantiate::<venue::client::Venue>(
            ALICE,
            venue::client::Terms {
                asset: XRD,
                price: PRICE,
                // The door admits nobody itself; its role is the pass.
                door: ALICE.address(),
            },
        );
        let hall = chain.instantiate::<venue::client::Venue>(
            ALICE,
            venue::client::Terms {
                asset: XRD,
                price: PRICE,
                door: door.address().into(),
            },
        );
        chain.credit(ALICE, XRD, 100);
        (door, hall)
    })
}

/// Pay, prove, spend the proof downstream: one transaction, completed.
#[hyperscale_vm_testing::test]
fn a_paid_pass_admits_its_holder(chain: &mut Chain) {
    let (door, hall) = world(chain);

    let outcome = chain.transact(ALICE, |b| {
        let payment = account::withdraw(b, ALICE, XRD, PRICE)?;
        let pass = door.pass(b, payment)?;
        b.presenting(pass, |b| hall.enter(b))
    });
    outcome.expect_completed();

    assert_eq!(outcome.answer(), 1, "the hall counted the entry");
    assert_eq!(chain.balance_of(door, venue::client::Till), PRICE);
    assert_eq!(chain.balance(ALICE, XRD), 90);
}

/// A short payment declines the prover, and the decline fails the
/// transaction wholesale — the gated call never ran.
#[hyperscale_vm_testing::test]
fn a_short_payment_declines_the_whole_transaction(chain: &mut Chain) {
    let (door, hall) = world(chain);

    chain
        .transact(ALICE, |b| {
            let payment = account::withdraw(b, ALICE, XRD, PRICE - 1)?;
            let pass = door.pass(b, payment)?;
            b.presenting(pass, |b| hall.enter(b))
        })
        .expect_declined(venue::Error::Short);

    assert_eq!(chain.balance(ALICE, XRD), 100, "a decline moves nothing");
    assert_eq!(chain.balance_of(door, venue::client::Till), 0);

    // The paid composition after it answers one: the declined entry was
    // never counted, so nothing downstream survived its evidence.
    let outcome = chain.transact(ALICE, |b| {
        let payment = account::withdraw(b, ALICE, XRD, PRICE)?;
        let pass = door.pass(b, payment)?;
        b.presenting(pass, |b| hall.enter(b))
    });
    outcome.expect_completed();
    assert_eq!(outcome.answer(), 1);
}
