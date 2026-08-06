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
}

#[test]
fn the_lowering_refuses_what_it_would_declare_wrongly() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/mode_mix.rs");
    refuse.compile_fail("tests/refusals/reassigned_key.rs");
    refuse.compile_fail("tests/refusals/early_return_output.rs");
}
