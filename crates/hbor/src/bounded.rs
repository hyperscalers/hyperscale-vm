//! Length-capped reads, and the byte-sequence fast path.
//!
//! These are what the derive emits for a `#[hbor(max = N)]` field and for a
//! `Vec<u8>` field. They are ordinary public functions: a hand-written impl
//! that wants a cap uses the same code the derive does, so the two cannot
//! disagree about where the check happens.
//!
//! Every cap here is checked against the claimed length *before* the
//! collection is built. That is a protocol bound, not the safety bound —
//! [`Decoder::read_len`] already rejects a length the remaining input cannot
//! satisfy, so allocation is bounded by input size whether or not a field
//! declares a cap.
//!
//! Each function is called through [`Decoder::descend`], by the derive or by
//! hand, so a capped field charges the same nesting depth as an uncapped one
//! of the same type.

use std::collections::{BTreeMap, BTreeSet};

use crate::HborDecode;
use crate::decode::Decoder;
use crate::encode::Encoder;
use crate::error::{DecodeError, EncodeError};

/// Write a byte sequence as a length then the bytes themselves.
///
/// The shape `Vec<u8>` would produce element by element, in one copy.
///
/// # Errors
///
/// [`EncodeError::LengthTooLarge`] for an inexpressible length.
pub fn encode_bytes(encoder: &mut Encoder<'_>, bytes: &[u8]) -> Result<(), EncodeError> {
    encoder.write_sized(bytes)
}

/// Read a byte sequence in one copy.
///
/// # Errors
///
/// [`DecodeError`] for a malformed or unsatisfiable length.
pub fn decode_bytes(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, DecodeError> {
    let len = decoder.read_len(1)?;
    Ok(decoder.read_slice(len)?.to_vec())
}

/// Read a byte sequence of at most `max` bytes.
///
/// # Errors
///
/// [`DecodeError::BoundExceeded`] past `max`, before anything is allocated.
pub fn decode_bounded_bytes(decoder: &mut Decoder<'_>, max: usize) -> Result<Vec<u8>, DecodeError> {
    let len = check(decoder.read_len(1)?, max)?;
    Ok(decoder.read_slice(len)?.to_vec())
}

/// Read a sequence of at most `max` elements.
///
/// # Errors
///
/// [`DecodeError::BoundExceeded`] past `max`, before anything is allocated.
pub fn decode_bounded_vec<T: HborDecode>(
    decoder: &mut Decoder<'_>,
    max: usize,
) -> Result<Vec<T>, DecodeError> {
    let len = check(decoder.read_len(T::MIN_ENCODED_LEN)?, max)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(decoder.nested()?);
    }
    Ok(out)
}

/// Read a string of at most `max` bytes.
///
/// The cap counts bytes, not characters — it bounds the wire, and a
/// character count would not.
///
/// # Errors
///
/// [`DecodeError::BoundExceeded`] past `max`, or
/// [`DecodeError::InvalidUtf8`].
pub fn decode_bounded_string(decoder: &mut Decoder<'_>, max: usize) -> Result<String, DecodeError> {
    let len = check(decoder.read_len(1)?, max)?;
    let bytes = decoder.read_slice(len)?;
    core::str::from_utf8(bytes)
        .map(ToOwned::to_owned)
        .map_err(|_| DecodeError::InvalidUtf8)
}

/// Read a set of at most `max` elements, ascending.
///
/// # Errors
///
/// [`DecodeError::BoundExceeded`] past `max`, or
/// [`DecodeError::UnsortedKeys`].
pub fn decode_bounded_btree_set<T: HborDecode + Ord>(
    decoder: &mut Decoder<'_>,
    max: usize,
) -> Result<BTreeSet<T>, DecodeError> {
    let len = check(decoder.read_len(T::MIN_ENCODED_LEN)?, max)?;
    let mut out = BTreeSet::new();
    for _ in 0..len {
        let element: T = decoder.nested()?;
        if out.last().is_some_and(|last| &element <= last) {
            return Err(DecodeError::UnsortedKeys);
        }
        out.insert(element);
    }
    Ok(out)
}

/// Read a map of at most `max` entries, ascending by key.
///
/// # Errors
///
/// [`DecodeError::BoundExceeded`] past `max`, or
/// [`DecodeError::UnsortedKeys`].
pub fn decode_bounded_btree_map<K: HborDecode + Ord, V: HborDecode>(
    decoder: &mut Decoder<'_>,
    max: usize,
) -> Result<BTreeMap<K, V>, DecodeError> {
    let len = check(
        decoder.read_len(K::MIN_ENCODED_LEN + V::MIN_ENCODED_LEN)?,
        max,
    )?;
    let mut out = BTreeMap::new();
    for _ in 0..len {
        let key: K = decoder.nested()?;
        let value: V = decoder.nested()?;
        if out.last_key_value().is_some_and(|(last, _)| &key <= last) {
            return Err(DecodeError::UnsortedKeys);
        }
        out.insert(key, value);
    }
    Ok(out)
}

/// Refuse an encode whose value outgrew the bound its field declares.
///
/// The derive calls this before writing a capped field. A value can only
/// reach here past its bound by being built past it, so this is the encoder
/// refusing to emit bytes its own decoder would reject.
///
/// # Errors
///
/// [`EncodeError::BoundExceeded`] past `max`.
pub const fn check_encoded_len(
    field: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), EncodeError> {
    if actual > max {
        return Err(EncodeError::BoundExceeded { field, actual, max });
    }
    Ok(())
}

const fn check(claimed: usize, max: usize) -> Result<usize, DecodeError> {
    if claimed > max {
        return Err(DecodeError::BoundExceeded {
            max,
            actual: claimed,
        });
    }
    Ok(claimed)
}

/// A `Vec<u8>` written by [`encode_bytes`] is byte-identical to one written
/// element by element, so the fast path is a speed choice and never a wire
/// choice.
#[cfg(test)]
mod tests {
    use super::{decode_bytes, encode_bytes};
    use crate::{DEFAULT_MAX_DEPTH, Decoder, Encoder, to_vec};

    #[test]
    fn the_byte_fast_path_matches_the_generic_encoding() {
        for case in [vec![], vec![0u8], vec![7u8; 200]] {
            let mut buf = Vec::new();
            let mut encoder = Encoder::new(&mut buf, DEFAULT_MAX_DEPTH);
            encode_bytes(&mut encoder, &case).unwrap();
            assert_eq!(buf, to_vec(&case).unwrap());

            let mut decoder = Decoder::new(&buf, DEFAULT_MAX_DEPTH);
            assert_eq!(decode_bytes(&mut decoder).unwrap(), case);
        }
    }
}
