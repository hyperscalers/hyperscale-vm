//! What the derive refuses, and where the message lands.
//!
//! A type with no canonical encoding is caught on the field the author
//! wrote, not as a missing impl on a generated line — so these pin the
//! diagnostics as much as the refusals. The toolchain is pinned exactly, so
//! matching compiler output is stable rather than brittle.

use trybuild::TestCases;

#[test]
fn the_derive_refuses_what_has_no_canonical_form() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/float_field.rs");
    refuse.compile_fail("tests/refusals/pointer_width_field.rs");
    refuse.compile_fail("tests/refusals/hash_collection_field.rs");
    refuse.compile_fail("tests/refusals/duplicate_discriminant.rs");
    refuse.compile_fail("tests/refusals/transparent_two_fields.rs");
    refuse.compile_fail("tests/refusals/transparent_skip_field.rs");
}

/// A shape is a static tree a type states as a constant, so a type that
/// reaches itself makes its constant name itself — and rustc refuses the
/// cycle on the impl, before any walk could spend a budget on it. The
/// type still derives its codec; what it has no claim to is a shape.
#[test]
fn a_recursive_type_has_no_static_shape() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/recursive_shape.rs");
    refuse.compile_fail("tests/refusals/transparent_unsigned_field.rs");
    refuse.compile_fail("tests/refusals/unknown_attribute.rs");
}

/// A preimage that does not mean what its declaration looks like is worse
/// than none: a marking that silently does nothing, a domain that separates
/// nothing, a signature covering nothing.
#[test]
fn the_derive_refuses_a_preimage_that_would_mislead() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/unsigned_without_domain.rs");
    refuse.compile_fail("tests/refusals/signing_context_without_domain.rs");
    refuse.compile_fail("tests/refusals/every_field_unsigned.rs");
    refuse.compile_fail("tests/refusals/signing_domain_on_enum.rs");
    refuse.compile_fail("tests/refusals/empty_signing_domain.rs");
}

// The zero-width sequence refusal is pinned by `compile_fail` doctests on
// `HborWidth` rather than here: it is a const-evaluation error at codegen,
// which trybuild's `cargo check` never reaches.

/// A tree whose leaves do not partition the value is not a tree over the
/// value, whatever it roots to.
#[test]
fn the_derive_refuses_a_tree_with_nothing_to_cover() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/merkle_unit_struct.rs");
    refuse.compile_fail("tests/refusals/merkle_transparent.rs");
    refuse.compile_fail("tests/refusals/merkle_without_domain.rs");
    refuse.compile_fail("tests/refusals/merkle_empty_domain.rs");
}

/// A member publishes under the identifier that declared it, and Rust
/// admits identifiers the protocol does not spell. The refusal lands on
/// the word an author has to change, rather than on the first table the
/// type is built into.
#[test]
fn the_derive_refuses_a_name_the_protocol_cannot_spell() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/name_the_protocol_cannot_spell.rs");
}
