//! What `#[blueprint]` refuses, and where the message lands.
//!
//! Every case is a body whose declaration would come out *smaller* than
//! what the body does if the lowering guessed — a dropped effect, a stale
//! key, an output the tail never declared. The macro's contract is that
//! its only failure mode is a hard error on the offending line, so these
//! pin the line as much as the refusal.

use trybuild::TestCases;

#[test]
fn the_lowering_refuses_what_it_cannot_see_into() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/self_call.rs");
    refuse.compile_fail("tests/refusals/self_escape.rs");
    refuse.compile_fail("tests/refusals/closure.rs");
    refuse.compile_fail("tests/refusals/unknown_macro.rs");
    refuse.compile_fail("tests/refusals/untyped_credit.rs");
}

#[test]
fn the_lowering_refuses_what_it_would_declare_wrongly() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/mode_mix.rs");
    refuse.compile_fail("tests/refusals/reassigned_key.rs");
    refuse.compile_fail("tests/refusals/early_return_output.rs");
    refuse.compile_fail("tests/refusals/two_denominations.rs");
}

/// A mark the macro can already tell is unsupportable, refused where the
/// author wrote it rather than at the publish gate.
///
/// The artifact scan belongs to the gate, because it reads compiled code
/// the macro has not produced yet. What a gate does is not: the attribute
/// sits right beside the claim, and a refusal that waits for a publish is
/// one the author meets as a metadata error about a package rather than
/// as a mistake on a line.
#[test]
fn the_lowering_refuses_a_mark_it_can_see_is_wrong() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/total_gated.rs");
}
