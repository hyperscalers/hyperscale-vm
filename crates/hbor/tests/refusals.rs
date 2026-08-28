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
    refuse.compile_fail("tests/refusals/cap_on_opaque_field.rs");
    refuse.compile_fail("tests/refusals/duplicate_discriminant.rs");
    refuse.compile_fail("tests/refusals/transparent_two_fields.rs");
    refuse.compile_fail("tests/refusals/transparent_skip_field.rs");
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
