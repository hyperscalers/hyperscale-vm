//! What the builder refuses at compile time, on the strength of an
//! address's class alone.
//!
//! The builder renders no judgement — admission re-derives everything it
//! enforces — so these are not new rules. They are the rules a class-typed
//! address moves out of admission's verdicts and into the type system:
//! naming code or a supply as a call target, or an account as a resource,
//! is a graph that does not compile rather than one that compiles and is
//! then refused. An address whose class has been forgotten is refused for
//! the same reason: whether it answers calls is precisely what was
//! forgotten.

//! The expectations quote the impl site, so a rustc upgrade or an edit to
//! the classes' own prose moves them: regenerate with `TRYBUILD=overwrite`
//! and read the diff, which is the compiler's explanation of the refusal.

use trybuild::TestCases;

#[test]
fn the_builder_refuses_a_target_that_answers_no_calls() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/package_target.rs");
    refuse.compile_fail("tests/refusals/untyped_target.rs");
}

#[test]
fn the_builder_refuses_a_resource_that_names_no_supply() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/account_as_resource.rs");
}
