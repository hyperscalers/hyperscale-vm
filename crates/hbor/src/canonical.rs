//! The canonicity harness.
//!
//! Canonicity says that if `decode(b)` succeeds then `encode(decode(b))` is
//! `b` again — one byte string per value, one value per byte string. That is
//! a claim about every byte string, not about the ones an encoder happens to
//! produce, so it cannot be checked by round-tripping alone.
//!
//! [`assert_canonical`] checks it where violations live: at the edges of a
//! real encoding. It re-encodes the value, appends a byte, truncates at
//! every offset, and flips bits at every offset, asserting that each result
//! either rejects or re-encodes to exactly itself. Non-minimal lengths,
//! unsorted maps, out-of-range discriminants, and trailing bytes are all
//! single-byte edits of a valid encoding, so this is where they surface.
//!
//! Consumers call this on their own types. It is the acceptance bar for a
//! codec impl, hand-written or derived, and a violation is a design-falsifying
//! event rather than a bug.

use core::fmt::Debug;

use crate::error::DecodeError;
use crate::{DEFAULT_MAX_DEPTH, HborDecode, HborEncode, from_slice_with_depth, to_vec_with_depth};

/// The bit patterns flipped at each offset. A low bit shifts a
/// discriminant or an ordering; the high bit toggles a length field's
/// continuation; all-ones lands well outside every valid narrow range.
const MUTATIONS: [u8; 3] = [0x01, 0x80, 0xFF];

/// Assert canonicity around `value`'s encoding.
///
/// # Panics
///
/// Panics with the offending byte string when the value does not round
/// trip, when trailing bytes are accepted, when a truncation decodes, or
/// when any single-byte mutant decodes to a value that re-encodes to
/// something other than the mutant itself.
pub fn assert_canonical<T>(value: &T)
where
    T: HborEncode + HborDecode + PartialEq + Debug,
{
    assert_canonical_at_depth(value, DEFAULT_MAX_DEPTH);
}

/// [`assert_canonical`] against a specific nesting cap.
///
/// # Panics
///
/// As [`assert_canonical`].
pub fn assert_canonical_at_depth<T>(value: &T, max_depth: usize)
where
    T: HborEncode + HborDecode + PartialEq + Debug,
{
    let bytes = to_vec_with_depth(value, max_depth)
        .unwrap_or_else(|e| panic!("encoding {value:?} failed: {e}"));

    let decoded = from_slice_with_depth::<T>(&bytes, max_depth)
        .unwrap_or_else(|e| panic!("re-decoding {value:?} failed: {e}"));
    assert_eq!(&decoded, value, "value changed across a round trip");

    let re_encoded = to_vec_with_depth(&decoded, max_depth)
        .unwrap_or_else(|e| panic!("re-encoding {decoded:?} failed: {e}"));
    assert_eq!(re_encoded, bytes, "one value produced two encodings");

    let mut extended = bytes.clone();
    extended.push(0);
    assert!(
        matches!(
            from_slice_with_depth::<T>(&extended, max_depth),
            Err(DecodeError::TrailingBytes { .. })
        ),
        "a trailing byte was accepted after {value:?}"
    );

    for cut in 0..bytes.len() {
        assert!(
            from_slice_with_depth::<T>(&bytes[..cut], max_depth).is_err(),
            "a {cut}-byte prefix of {value:?} decoded as a complete value"
        );
    }

    for offset in 0..bytes.len() {
        for mutation in MUTATIONS {
            let mut mutant = bytes.clone();
            mutant[offset] ^= mutation;
            if mutant == bytes {
                continue;
            }
            // Rejecting is always allowed. Accepting is allowed only if the
            // decoded value's own encoding is the mutant — otherwise two
            // byte strings mean one value.
            if let Ok(other) = from_slice_with_depth::<T>(&mutant, max_depth) {
                let round_tripped = to_vec_with_depth(&other, max_depth)
                    .unwrap_or_else(|e| panic!("re-encoding a mutant of {value:?} failed: {e}"));
                assert_eq!(
                    round_tripped, mutant,
                    "byte {offset} of {value:?} mutated by {mutation:#04x} decoded to \
                     {other:?}, which encodes to different bytes"
                );
            }
        }
    }
}
