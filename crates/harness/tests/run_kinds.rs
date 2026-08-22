//! Which run kinds the corpus reaches, held to a list.
//!
//! Nine resources were built and a missed one is a runtime refusal
//! rather than a build failure: the world names every kind whether or
//! not a package ever asks for one, so nothing about compiling the
//! corpus says a kind was ever lent. This reads the kinds off the
//! declarations the corpus traces, which is where a site's mode is
//! decided, and holds them to what the fixtures actually exercise.
//!
//! The list is a floor and a ceiling both. A kind that drops off it is
//! coverage lost; a kind that appears on it is a fixture nobody wrote
//! down here.

use std::collections::BTreeSet;

use hyperscale_vm_effects::{AbiParam, Clause, MethodSignature, materialized_kind};
use hyperscale_vm_fixtures::grammar;
use hyperscale_vm_types::CellKind;

/// The kind a run binding is lent at: the mode the site it names
/// materialises, which is the declaration's answer rather than the
/// export's.
fn run_kind(signature: &MethodSignature, clause: u32, site: u32) -> Option<CellKind> {
    let Clause::ForEach { body, .. } = signature.effects.get(clause as usize)? else {
        return None;
    };
    materialized_kind(body.get(site as usize)?)
}

/// Every run the corpus package lends, by the world type it is
/// borrowed as — the name, because a kind is not ordered and the name
/// is what a reader of a failure wants anyway.
fn reached() -> BTreeSet<&'static str> {
    grammar::metadata()
        .methods
        .values()
        .flat_map(|signature| {
            signature.abi.iter().filter_map(move |param| match param {
                AbiParam::Run { clause, site } => {
                    run_kind(signature, *clause, *site).map(CellKind::run_type)
                }
                _ => None,
            })
        })
        .collect()
}

#[test]
fn the_corpus_lends_every_run_kind_a_body_can_reach() {
    let reached = reached();
    let expected = BTreeSet::from([
        CellKind::Read.run_type(),
        CellKind::Write.run_type(),
        CellKind::Amount.run_type(),
        CellKind::AmountRead.run_type(),
        CellKind::Delta.run_type(),
        CellKind::Reserve.run_type(),
        CellKind::RangeRead.run_type(),
        CellKind::RangeWrite.run_type(),
    ]);
    assert_eq!(reached, expected, "the run kinds the corpus lends moved");
}

#[test]
fn a_holdings_interval_is_the_one_kind_no_body_reaches() {
    // Not an omission. `InstanceRange` is an interval that moves value,
    // and the only one is `holdings(resource)` — a package cannot
    // declare a collection of instances of its own. So a run over one
    // needs a value-moving clause per element, and both directions are
    // closed: a take names ids that must be derivable from the method's
    // arguments, and a file carries an edge the interval's cap is
    // derived from, which a body-produced bucket is not. A method has a
    // fixed argument list, so one edge cannot serve every element.
    //
    // What would open it is narrow: letting a file derive its cap from a
    // take of the same derivable ids at the same site. That is a change
    // to how the cap is derived, not a fixture nobody has written.
    assert!(
        !reached().contains(CellKind::InstanceRange.run_type()),
        "a body reaches the holdings interval now — the reasoning above is stale",
    );
}
