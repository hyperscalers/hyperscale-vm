//! A configuration no constructor would have written is refused where
//! the component becomes actual.
//!
//! A typed client cannot write a bounded slot past its range, but a raw
//! manifest can, and the seal binds the record as bytes. The bring-up
//! reads every slot whose cell reading can refuse, so the instance traps
//! before it exists rather than in the first method that consults the
//! slot — created, bricked, and holding funds.

use hyperscale_vm_effects::Value;
use hyperscale_vm_fixtures::perp;
use hyperscale_vm_sdk::state::UnitFixed;
use hyperscale_vm_testing::{Chain, PrincipalAddr, ResourceAddr, package, principal, resource};

const ALICE: PrincipalAddr = principal(1);
const X: ResourceAddr = resource(0xE1);

/// The market's raw slots, with the maintenance margin as given.
fn terms(maintenance_margin: u128) -> Vec<Value> {
    vec![
        Value::Address(X.address()),
        Value::Address(ALICE.address()),
        Value::U128(maintenance_margin),
        Value::U128(UnitFixed::bps(100).expect("one percent").scaled()),
        Value::Bool(true),
    ]
}

/// The control: the same raw slots within range bring the market up.
#[test]
fn a_bounded_slot_within_range_brings_up() {
    let mut chain = Chain::native();
    let package = chain.publish(package!(perp));
    let market = chain.derive_raw(
        package,
        terms(UnitFixed::bps(500).expect("five percent").scaled()),
    );
    chain.bring_up(ALICE, market, ()).expect_completed();
}

/// A margin past one is refused at the bring-up, by the same reading a
/// method would have tripped over later.
#[test]
fn a_bounded_slot_past_its_range_traps_at_the_bring_up() {
    let mut chain = Chain::native();
    let package = chain.publish(package!(perp));
    let market = chain.derive_raw(package, terms(UnitFixed::ONE.scaled() + 1));
    let outcome = chain.bring_up(ALICE, market, ());
    assert!(
        !outcome.completed(),
        "a margin past one must not bring the market up"
    );
    assert!(
        outcome.refused_as().contains("Unreachable"),
        "the bring-up traps on the slot: {}",
        outcome.refused_as()
    );
}
