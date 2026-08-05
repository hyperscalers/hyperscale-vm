//! Impls for the variable-length types.
//!
//! Each carries a minimal length field, then its elements. The length is
//! checked against what the remaining input could hold before anything is
//! allocated, so a claimed length never buys more memory than the peer paid
//! for in bytes.
//!
//! `BTreeMap` and `BTreeSet` encode in ascending key order and reject input
//! that is not — an unsorted payload would be a second byte string for a
//! value that already has one. `HashMap` and `HashSet` have no impl: their
//! iteration order is undefined, so they have no canonical encoding to
//! give.
//!
//! `Vec<u8>` decodes element by element here. The derive emits a direct
//! slice copy when it sees the type syntactically, which is where the
//! common case is worth specializing; a generic impl cannot be.

use std::collections::{BTreeMap, BTreeSet};

use crate::decode::Decoder;
use crate::encode::Encoder;
use crate::error::{DecodeError, EncodeError};
use crate::{HborDecode, HborEncode};

impl<T: HborEncode> HborEncode for Vec<T> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_len(self.len())?;
        for element in self {
            encoder.nested(element)?;
        }
        Ok(())
    }
}

impl<T: HborDecode> HborDecode for Vec<T> {
    const MIN_ENCODED_LEN: usize = 1;

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let len = decoder.read_len(T::MIN_ENCODED_LEN)?;
        let mut out = Self::with_capacity(len);
        for _ in 0..len {
            out.push(decoder.nested()?);
        }
        Ok(out)
    }
}

impl HborEncode for String {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_sized(self.as_bytes())
    }
}

impl HborDecode for String {
    const MIN_ENCODED_LEN: usize = 1;

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

impl<T: HborEncode> HborEncode for BTreeSet<T> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_len(self.len())?;
        for element in self {
            encoder.nested(element)?;
        }
        Ok(())
    }
}

impl<T: HborDecode + Ord> HborDecode for BTreeSet<T> {
    const MIN_ENCODED_LEN: usize = 1;

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let len = decoder.read_len(T::MIN_ENCODED_LEN)?;
        let mut out = Self::new();
        for _ in 0..len {
            let element: T = decoder.nested()?;
            // Strictly ascending, so this rejects duplicates too: a
            // repeated element would decode to a set the input does not
            // describe.
            if out.last().is_some_and(|last| &element <= last) {
                return Err(DecodeError::UnsortedKeys);
            }
            out.insert(element);
        }
        Ok(out)
    }
}

impl<K: HborEncode, V: HborEncode> HborEncode for BTreeMap<K, V> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_len(self.len())?;
        for (key, value) in self {
            encoder.nested(key)?;
            encoder.nested(value)?;
        }
        Ok(())
    }
}

impl<K: HborDecode + Ord, V: HborDecode> HborDecode for BTreeMap<K, V> {
    const MIN_ENCODED_LEN: usize = 1;

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let len = decoder.read_len(K::MIN_ENCODED_LEN + V::MIN_ENCODED_LEN)?;
        let mut out = Self::new();
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
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::canonical::assert_canonical;
    use crate::error::DecodeError;
    use crate::{from_slice, to_vec};

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
