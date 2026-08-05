//! Impls for the variable-length types.
//!
//! Each carries a minimal length field, then its elements. The length is
//! checked against what the remaining input could hold before anything is
//! allocated, and the reservation hint is capped by the bytes that remain,
//! so a claimed length never reserves more memory than the peer paid for in
//! bytes.
//!
//! Element types must have a nonzero minimum width, checked at compile
//! time. A sequence of zero-width values is a count in disguise: no input
//! can pay for its length, and the honest encoding of a count is the count.
//!
//! `BTreeMap` and `BTreeSet` encode in ascending key order and reject input
//! that is not — an unsorted payload would be a second byte string for a
//! value that already has one. `HashMap` and `HashSet` have no impl: their
//! iteration order is undefined, so they have no canonical encoding to
//! give.
//!
//! Every variable-length body charges exactly one nesting level for its
//! elements, present or not — so an empty sequence, a full one, a capped
//! field, and the byte fast path all accept and refuse at the same caps.
//!
//! `Vec<u8>` decodes element by element here. The derive emits a direct
//! slice copy when it sees the type syntactically, which is where the
//! common case is worth specializing; a generic impl cannot be.

use std::collections::{BTreeMap, BTreeSet};

use crate::decode::Decoder;
use crate::encode::Encoder;
use crate::error::{DecodeError, EncodeError};
use crate::{HborDecode, HborEncode, HborWidth};

/// The compile-time refusal of zero-width sequence elements, shared by
/// every variable-length impl and by the capped readers in
/// [`bounded`](crate::bounded).
macro_rules! refuse_zero_width_elements {
    ($width:expr) => {
        const {
            assert!(
                $width > 0,
                "a sequence over zero-width elements is a count in disguise; encode the count"
            );
        }
    };
}
pub(crate) use refuse_zero_width_elements;

impl<T> HborWidth for Vec<T> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<T: HborEncode> HborEncode for Vec<T> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        refuse_zero_width_elements!(T::MIN_ENCODED_LEN);
        encoder.write_len(self.len())?;
        // One level for the elements, charged whether or not any exist, so
        // an empty sequence, a full one, and the byte fast path all agree
        // at every cap.
        encoder.descend(|encoder| {
            for element in self {
                element.encode(encoder)?;
            }
            Ok(())
        })
    }
}

impl<T: HborDecode> HborDecode for Vec<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        refuse_zero_width_elements!(T::MIN_ENCODED_LEN);
        let len = decoder.read_len(T::MIN_ENCODED_LEN)?;
        let mut out = Self::with_capacity(decoder.reserve_hint::<T>(len));
        decoder.descend(|decoder| {
            for _ in 0..len {
                out.push(T::decode(decoder)?);
            }
            Ok(())
        })?;
        Ok(out)
    }
}

impl HborWidth for String {
    const MIN_ENCODED_LEN: usize = 1;
}

impl HborEncode for String {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_sized(self.as_bytes())
    }
}

impl HborDecode for String {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let len = decoder.read_len(1)?;
        let bytes = decoder.read_slice(len)?;
        // UTF-8 validation is a canonicity check as much as a type check:
        // overlong sequences encode a scalar that already has a shorter
        // form, and `from_utf8` rejects them.
        core::str::from_utf8(bytes)
            .map(ToOwned::to_owned)
            .map_err(|_| DecodeError::InvalidUtf8)
    }
}

impl<T> HborWidth for BTreeSet<T> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<T: HborEncode> HborEncode for BTreeSet<T> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        refuse_zero_width_elements!(T::MIN_ENCODED_LEN);
        encoder.write_len(self.len())?;
        encoder.descend(|encoder| {
            for element in self {
                element.encode(encoder)?;
            }
            Ok(())
        })
    }
}

impl<T: HborDecode + Ord> HborDecode for BTreeSet<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        refuse_zero_width_elements!(T::MIN_ENCODED_LEN);
        let len = decoder.read_len(T::MIN_ENCODED_LEN)?;
        let mut out = Self::new();
        decoder.descend(|decoder| {
            for _ in 0..len {
                let element = T::decode(decoder)?;
                // Strictly ascending, so this rejects duplicates too: a
                // repeated element would decode to a set the input does
                // not describe.
                if out.last().is_some_and(|last| &element <= last) {
                    return Err(DecodeError::UnsortedKeys);
                }
                out.insert(element);
            }
            Ok(())
        })?;
        Ok(out)
    }
}

impl<K, V> HborWidth for BTreeMap<K, V> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<K: HborEncode, V: HborEncode> HborEncode for BTreeMap<K, V> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        refuse_zero_width_elements!(K::MIN_ENCODED_LEN + V::MIN_ENCODED_LEN);
        encoder.write_len(self.len())?;
        encoder.descend(|encoder| {
            for (key, value) in self {
                key.encode(encoder)?;
                value.encode(encoder)?;
            }
            Ok(())
        })
    }
}

impl<K: HborDecode + Ord, V: HborDecode> HborDecode for BTreeMap<K, V> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        refuse_zero_width_elements!(K::MIN_ENCODED_LEN + V::MIN_ENCODED_LEN);
        let len = decoder.read_len(K::MIN_ENCODED_LEN + V::MIN_ENCODED_LEN)?;
        let mut out = Self::new();
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
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::canonical::assert_canonical;
    use crate::decode::Decoder;
    use crate::error::DecodeError;
    use crate::{DEFAULT_MAX_DEPTH, from_slice, to_vec, varint};

    #[test]
    fn a_sequence_is_a_length_then_its_elements() {
        assert_eq!(to_vec(&vec![1u8, 2, 3]).unwrap(), vec![3, 1, 2, 3]);
        assert_eq!(to_vec(&Vec::<u8>::new()).unwrap(), vec![0]);
        assert_eq!(to_vec(&"hi".to_owned()).unwrap(), vec![2, b'h', b'i']);
    }

    #[test]
    fn a_length_the_input_cannot_satisfy_rejects_before_allocating() {
        // Claims 200 million 32-byte elements with three bytes on hand.
        let bytes = [0x80, 0x88, 0x8Bu8, 0x01];
        let err = from_slice::<Vec<[u8; 32]>>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::LengthExceedsInput { .. }));
    }

    #[test]
    fn a_length_field_that_is_not_minimal_rejects() {
        // Length 1 written in two bytes, then one element.
        assert_eq!(
            from_slice::<Vec<u8>>(&[0x81, 0x00, 0x07]),
            Err(DecodeError::NonMinimalLength)
        );
    }

    #[test]
    fn unsorted_and_duplicate_entries_reject() {
        assert_eq!(
            from_slice::<BTreeSet<u8>>(&[2, 5, 3]),
            Err(DecodeError::UnsortedKeys)
        );
        assert_eq!(
            from_slice::<BTreeSet<u8>>(&[2, 5, 5]),
            Err(DecodeError::UnsortedKeys)
        );
        assert_eq!(
            from_slice::<BTreeMap<u8, u8>>(&[2, 5, 0, 3, 0]),
            Err(DecodeError::UnsortedKeys)
        );
        assert_eq!(
            from_slice::<BTreeMap<u8, u8>>(&[2, 5, 0, 5, 1]),
            Err(DecodeError::UnsortedKeys)
        );
    }

    #[test]
    fn invalid_utf8_rejects() {
        assert_eq!(
            from_slice::<String>(&[1, 0xFF]),
            Err(DecodeError::InvalidUtf8)
        );
        // An overlong encoding of '/', which has a one-byte form.
        assert_eq!(
            from_slice::<String>(&[2, 0xC0, 0xAF]),
            Err(DecodeError::InvalidUtf8)
        );
    }

    /// The audit's amplification case: half a million one-byte empty inner
    /// vectors. The claimed length passes the width check, so the value
    /// decodes — the hint just must not reserve two dozen bytes per input
    /// byte ahead of validation.
    #[test]
    fn a_reservation_never_exceeds_the_input() {
        let count = 500_000;
        let mut input = Vec::with_capacity(count + 4);
        varint::write(&mut input, count).unwrap();
        input.extend(std::iter::repeat_n(0u8, count));

        let hint = Decoder::new(&input, DEFAULT_MAX_DEPTH).reserve_hint::<Vec<u8>>(count);
        assert!(
            hint * size_of::<Vec<u8>>() <= input.len(),
            "a hint of {hint} elements reserves more bytes than the input holds"
        );

        // The value itself still decodes in full; the cap is on the
        // up-front reservation, not on what a valid sequence may grow to.
        let decoded: Vec<Vec<u8>> = from_slice(&input).unwrap();
        assert_eq!(decoded.len(), count);
    }

    #[test]
    fn collections_are_canonical() {
        assert_canonical(&Vec::<u8>::new());
        assert_canonical(&vec![1u8, 2, 3]);
        assert_canonical(&vec![vec![1u16], vec![], vec![2, 3]]);
        assert_canonical(&String::new());
        assert_canonical(&"hbor".to_owned());
        assert_canonical(&BTreeSet::from([1u8, 3, 7]));
        assert_canonical(&BTreeMap::from([(1u8, 10u32), (2, 20)]));
        assert_canonical(&vec![Some(1u8), None, Some(3)]);
    }
}
