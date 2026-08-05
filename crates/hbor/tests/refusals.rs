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
    refuse.compile_fail("tests/refusals/unknown_attribute.rs");
}
