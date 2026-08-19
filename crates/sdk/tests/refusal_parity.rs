//! The tracer refuses what the macro refuses.
//!
//! The macro restates tracer policy so refusals get spans: a gate or a
//! denomination the vocabulary has no rule for is refused on the line
//! that wrote it, where the tracer could only panic inside a generated
//! `blueprint()`. `stdlib_parity` pins the accept side of that
//! mirroring; this lane pins the refuse side, driving the tracer through
//! each shape a `tests/refusals/` fixture proves the macro refuses —
//! `vacuous_threshold`, `degenerate_threshold`, `wide_threshold`,
//! `nested_threshold`, `two_denominations` — and holding it to the same
//! verdict. The threshold node's count and width share one predicate
//! (`well_formed`, which the stored rule's decode gate also applies), so
//! only the depth relationship and the denomination merge are held here
//! by boundary rather than by construction: each cap is pinned from both
//! sides, the deepest admissible tree beside the shallowest refused one.

use hyperscale_vm_effects::ParamType;
use hyperscale_vm_sdk::sym::{Addr, Sym};
use hyperscale_vm_sdk::{Blueprint, Trace};

/// A one-method blueprint whose gate is whatever `rule` builds.
fn gated(rule: impl Fn(&mut Trace) + 'static) {
    let _ = Blueprint::builder().method("gated", &[], move |t: &mut Trace| rule(t));
}

/// The deepest admissible tree is admitted: three threshold levels with
/// leaves at the fourth, which is exactly `MAX_RULE_DEPTH` levels in
/// all. The refusal one level past it is real because this is not.
#[test]
fn the_deepest_admissible_gate_traces() {
    gated(|t| {
        let key: Sym<Addr> = t.config(0);
        let rule = t.n_of(1, vec![t.n_of(1, vec![t.n_of(1, vec![t.claim(&key)])])]);
        t.guarded_by(rule);
    });
}

/// One level past the cap: the tree `nested_threshold.rs` proves the
/// macro refuses on its own line.
#[test]
#[should_panic(expected = "nests past")]
fn a_gate_past_the_depth_cap_fails_the_build() {
    gated(|t| {
        let key: Sym<Addr> = t.config(0);
        let deepest = t.n_of(1, vec![t.n_of(1, vec![t.n_of(1, vec![t.claim(&key)])])]);
        let rule = t.n_of(1, vec![deepest]);
        t.guarded_by(rule);
    });
}

/// The count the whole branch width meets is admitted; the shapes on
/// either side of it are the two refusals below.
#[test]
fn a_threshold_met_by_every_branch_traces() {
    gated(|t| {
        let key: Sym<Addr> = t.config(0);
        let rule = t.n_of(2, vec![t.claim(&key), t.claim(&key)]);
        t.guarded_by(rule);
    });
}

/// The tree `vacuous_threshold.rs` proves the macro refuses.
#[test]
#[should_panic(expected = "a threshold requiring nothing would admit anyone")]
fn a_threshold_requiring_nothing_fails_the_build() {
    gated(|t| {
        let key: Sym<Addr> = t.config(0);
        let rule = t.n_of(0, vec![t.claim(&key), t.claim(&key)]);
        t.guarded_by(rule);
    });
}

/// The tree `degenerate_threshold.rs` proves the macro refuses.
#[test]
#[should_panic(expected = "would admit no one")]
fn a_threshold_no_one_meets_fails_the_build() {
    gated(|t| {
        let key: Sym<Addr> = t.config(0);
        let rule = t.n_of(3, vec![t.claim(&key), t.claim(&key)]);
        t.guarded_by(rule);
    });
}

/// The widest admissible threshold is admitted, so the width refusal
/// below sits one branch past a real boundary.
#[test]
fn the_widest_admissible_threshold_traces() {
    gated(|t| {
        let key: Sym<Addr> = t.config(0);
        let branches: Vec<_> = (0..16).map(|_| t.claim(&key)).collect();
        let rule = t.n_of(1, branches);
        t.guarded_by(rule);
    });
}

/// The tree `wide_threshold.rs` proves the macro refuses.
#[test]
#[should_panic(expected = "branches wider than the vocabulary admits")]
fn a_threshold_past_the_branch_cap_fails_the_build() {
    gated(|t| {
        let key: Sym<Addr> = t.config(0);
        let branches: Vec<_> = (0..17).map(|_| t.claim(&key)).collect();
        let rule = t.n_of(1, branches);
        t.guarded_by(rule);
    });
}

/// One edge credited twice to one resource is one denomination, which is
/// what makes the contradiction below a contradiction.
#[test]
fn one_resource_twice_is_one_denomination() {
    let _ = Blueprint::builder().method("credit", &[ParamType::Bucket], |t: &mut Trace| {
        let x: Sym<Addr> = t.config(0);
        t.denomination(0, &x);
        t.denomination(0, &x);
    });
}

/// The shape `two_denominations.rs` proves the macro refuses: an edge
/// credited to cells keyed by two resources, which no edge carries.
#[test]
#[should_panic(expected = "no edge carries both")]
fn two_unconditional_denominations_fail_the_build() {
    let _ = Blueprint::builder().method("credit", &[ParamType::Bucket], |t: &mut Trace| {
        let x: Sym<Addr> = t.config(0);
        let y: Sym<Addr> = t.config(1);
        t.denomination(0, &x);
        t.denomination(0, &y);
    });
}
