//! Length-capped reads, and the byte-sequence fast path.
//!
//! These are what the derive emits for a `#[hbor(max = N)]` field and for a
//! `Vec<u8>` field. They are ordinary public functions: a hand-written impl
//! that wants a cap uses the same code the derive does, so the two cannot
//! disagree about where the check happens.
//!
//! Every cap here is checked against the claimed length *before* the
//! collection is built. That is a protocol bound layered over the wire-level
//! one — [`Decoder::read_len`] already rejects a length the remaining input
//! cannot satisfy, and the reservation hint is capped by the bytes that
//! remain, whether or not a field declares a cap. What only the cap can
//! bound is an accepted value's footprint, which exceeds its encoding by a
//! per-type constant the wire never sees.
//!
//! Each function is called through [`Decoder::descend`], by the derive or by
//! hand, and every variable-length body charges one further level for its
//! elements, present or not — so a capped field, an uncapped field, and
//! either spelling of a byte sequence all charge the same nesting depth.

use std::collections::{BTreeMap, BTreeSet};

use crate::HborDecode;
use crate::collection::refuse_zero_width_elements;
use crate::decode::Decoder;
use crate::encode::{Encoder, Sink};
use crate::error::{DecodeError, EncodeError};

/// Write a byte sequence as a length then the bytes themselves.
///
/// The shape `Vec<u8>` would produce element by element, in one copy.
///
/// # Errors
///
/// [`EncodeError::LengthTooLarge`] for an inexpressible length, or
/// [`EncodeError::DepthExceeded`] at the cap.
pub fn encode_bytes<S: Sink>(encoder: &mut Encoder<S>, bytes: &[u8]) -> Result<(), EncodeError> {
    encoder.write_len(bytes.len())?;
    // The element level, charged around one copy instead of per byte: the
    // fast path is a speed choice, and both spellings of the same bytes
    // must succeed or fail together at every cap.
    encoder.descend(|encoder| {
        encoder.write_fixed(bytes);
        Ok(())
    })
}

/// Read a byte sequence in one copy.
///
/// # Errors
///
/// [`DecodeError`] for a malformed or unsatisfiable length, or a payload
/// past the depth cap.
pub fn decode_bytes(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, DecodeError> {
    let len = decoder.read_len(1)?;
    decoder.descend(|decoder| Ok(decoder.read_slice(len)?.to_vec()))
}

/// Read a byte sequence of at most `max` bytes.
///
/// # Errors
///
/// [`DecodeError::BoundExceeded`] past `max`, before anything is allocated.
pub fn decode_bounded_bytes(decoder: &mut Decoder<'_>, max: usize) -> Result<Vec<u8>, DecodeError> {
    let len = check(decoder.read_len(1)?, max)?;
    decoder.descend(|decoder| Ok(decoder.read_slice(len)?.to_vec()))
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
    refuse_zero_width_elements!(T::MIN_ENCODED_LEN);
    let len = check(decoder.read_len(T::MIN_ENCODED_LEN)?, max)?;
    let mut out = Vec::with_capacity(decoder.reserve_hint::<T>(len));
    decoder.descend(|decoder| {
        for _ in 0..len {
            out.push(T::decode(decoder)?);
        }
        Ok(())
    })?;
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
    refuse_zero_width_elements!(T::MIN_ENCODED_LEN);
    let len = check(decoder.read_len(T::MIN_ENCODED_LEN)?, max)?;
    let mut out = BTreeSet::new();
    decoder.descend(|decoder| {
        for _ in 0..len {
            let element = T::decode(decoder)?;
            if out.last().is_some_and(|last| &element <= last) {
                return Err(DecodeError::UnsortedKeys);
            }
            out.insert(element);
        }
        Ok(())
    })?;
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
    refuse_zero_width_elements!(K::MIN_ENCODED_LEN + V::MIN_ENCODED_LEN);
    let len = check(
        decoder.read_len(K::MIN_ENCODED_LEN + V::MIN_ENCODED_LEN)?,
        max,
    )?;
    let mut out = BTreeMap::new();
    decoder.descend(|decoder| {
        for _ in 0..len {
            let key = K::decode(decoder)?;
            let value = V::decode(decoder)?;
            if out.last_key_value().is_some_and(|(last, _)| &key <= last) {
                return Err(DecodeError::UnsortedKeys);
            }
            out.insert(key, value);
        }
        Ok(())
    })?;
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
/// element by element and charges the same depth, so the fast path is a
/// speed choice — never a wire choice, and never a depth choice.
#[cfg(test)]
mod tests {
    use super::{decode_bytes, encode_bytes};
    use crate::{
        DEFAULT_MAX_DEPTH, Decoder, Encoder, from_slice_with_depth, to_vec, to_vec_with_depth,
    };

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

    /// Both spellings must accept and refuse at the same caps, or a
    /// payload's fate would depend on how the type reading it was written.
    #[test]
    fn the_byte_fast_path_charges_the_generic_depth() {
        let case = vec![7u8; 4];
        let bytes = to_vec(&case).unwrap();
        for cap in 0..3 {
            let generic = from_slice_with_depth::<Vec<u8>>(&bytes, cap).is_ok();

            let mut decoder = Decoder::new(&bytes, cap);
            let fast = decode_bytes(&mut decoder).is_ok();
            assert_eq!(generic, fast, "decode at cap {cap}");

            let generic = to_vec_with_depth(&case, cap).is_ok();
            let mut buf = Vec::new();
            let mut encoder = Encoder::new(&mut buf, cap);
            let fast = encode_bytes(&mut encoder, &case).is_ok();
            assert_eq!(generic, fast, "encode at cap {cap}");
        }
    }
}
