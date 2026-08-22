//! Which run kinds the corpus lends, held to a list.
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
//! down here. It is every kind there is, so the floor is the whole
//! world.

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
fn the_corpus_lends_every_run_kind_there_is() {
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
        CellKind::InstanceRange.run_type(),
    ]);
    assert_eq!(reached, expected, "the run kinds the corpus lends moved");
}
