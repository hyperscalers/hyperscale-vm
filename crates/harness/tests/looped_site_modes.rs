//! Which modes the corpus lends through a looped site, held to a list.
//!
//! A site is one resource whichever mode its elements carry, so nothing
//! about compiling the corpus says a mode was ever lent through one —
//! the capability behind an element is the kernel's answer, and a mode
//! the fixtures never reach is coverage nobody would miss. This reads
//! the modes off the declarations the corpus traces, which is where a
//! site's mode is decided, and holds them to what the fixtures exercise.
//!
//! The list is a floor and a ceiling both. A mode that drops off it is
//! coverage lost; a mode that appears on it is a fixture nobody wrote
//! down here.
//!
//! It is every pairing a looped site can carry but one: the corpus
//! reaches the crediting half of a movement and not the unrestricted
//! half, which is a fixture to write rather than a rule.

use std::collections::BTreeSet;

use hyperscale_vm_effects::{AbiParam, Clause, MethodSignature, ModeExpr, TargetExpr};
use hyperscale_vm_fixtures::grammar;

/// How a looped site's declaration reads: its mode, and whether the
/// target is a single leaf or an interval, and whether it holds value.
fn looped_mode(signature: &MethodSignature, clause: u32, site: u32) -> Option<&'static str> {
    let Clause::ForEach { body, .. } = signature.effects.get(clause as usize)? else {
        return None;
    };
    let Clause::Effect {
        reach: None,
        target,
        mode,
        denomination,
        ..
    } = body.get(site as usize)?
    else {
        return None;
    };
    let holds_value = denomination.is_some();
    Some(match (target, mode) {
        (TargetExpr::Point(_), ModeExpr::Read) if holds_value => "read of value",
        (TargetExpr::Point(_), ModeExpr::Read) => "read of bytes",
        (TargetExpr::Point(_), ModeExpr::Write) if holds_value => "exclusive hold on value",
        (TargetExpr::Point(_), ModeExpr::Write) => "exclusive hold on bytes",
        (TargetExpr::Point(_), ModeExpr::Delta) => "commutative movement",
        (TargetExpr::Point(_), ModeExpr::Credit) => "commutative credit",
        (TargetExpr::Point(_), ModeExpr::Reserve(_)) => "held reservation",
        (TargetExpr::Entry { .. } | TargetExpr::Range { .. }, ModeExpr::Read) => "read interval",
        (TargetExpr::Entry { .. } | TargetExpr::Range { .. }, ModeExpr::Write) if holds_value => {
            "interval of instances"
        }
        (TargetExpr::Entry { .. } | TargetExpr::Range { .. }, ModeExpr::Write) => "write interval",
        _ => return None,
    })
}

/// Every mode the corpus package lends through a looped site.
fn reached() -> BTreeSet<&'static str> {
    grammar::metadata()
        .methods
        .values()
        .flat_map(|signature| {
            signature.abi.iter().filter_map(move |param| match param {
                AbiParam::Handle { clause, site } => looped_mode(signature, *clause, *site),
                _ => None,
            })
        })
        .collect()
}

#[test]
fn the_corpus_lends_every_mode_a_looped_site_can_carry() {
    let reached = reached();
    let expected = BTreeSet::from([
        "read of bytes",
        "read of value",
        "exclusive hold on bytes",
        "exclusive hold on value",
        "commutative credit",
        "held reservation",
        "read interval",
        "write interval",
        "interval of instances",
    ]);
    assert_eq!(reached, expected, "the modes the corpus lends moved");
}
