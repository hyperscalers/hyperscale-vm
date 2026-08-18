//! The length field: minimal LEB128, four bytes at most.
//!
//! Lengths are the only variable-width integers on the wire — every other
//! integer is a schema-fixed width. Minimality is checked on read, not
//! assumed from the writer: a length with a redundant continuation byte is a
//! second encoding of a value that already has one.

use crate::error::{DecodeError, EncodeError};

/// The largest expressible length. Four LEB128 bytes carry 28 bits.
pub const MAX_LENGTH: usize = 0x0FFF_FFFF;

/// Append `value` as a minimal LEB128 length.
///
/// # Errors
///
/// [`EncodeError::LengthTooLarge`] when `value` exceeds [`MAX_LENGTH`].
pub fn write(buf: &mut Vec<u8>, value: usize) -> Result<(), EncodeError> {
    let (bytes, len) = encode(value)?;
    if let Some(field) = bytes.get(..len) {
        buf.extend_from_slice(field);
    }
    Ok(())
}

/// The bytes of `value` as a minimal LEB128 length, and how many there
/// are.
///
/// Returned in a fixed array rather than pushed into a buffer, because
/// the caller may be writing into one it cannot grow.
///
/// # Errors
///
/// [`EncodeError::LengthTooLarge`] when `value` exceeds [`MAX_LENGTH`].
pub fn encode(value: usize) -> Result<([u8; 4], usize), EncodeError> {
    if value > MAX_LENGTH {
        return Err(EncodeError::LengthTooLarge {
            actual: value,
            max: MAX_LENGTH,
        });
    }
    let mut out = [0u8; 4];
    let mut rest = value;
    let mut len = 0;
    loop {
        #[allow(clippy::cast_possible_truncation)] // masked to seven bits
        let seven = (rest & 0x7F) as u8;
        rest >>= 7;
        // Four bytes carry every admissible length, and the check above
        // is what makes this loop terminate inside them.
        if let Some(slot) = out.get_mut(len) {
            *slot = if rest == 0 { seven } else { seven | 0x80 };
        }
        len += 1;
        if rest == 0 {
            return Ok((out, len));
        }
    }
}

/// Read a minimal LEB128 length from the front of `bytes`, returning the
/// value and the number of bytes it consumed.
///
/// # Errors
///
/// [`DecodeError::UnexpectedEof`] when the field is cut short,
/// [`DecodeError::LengthTooLarge`] past four bytes, and
/// [`DecodeError::NonMinimalLength`] when a shorter encoding of the same
/// value exists.
pub fn read(bytes: &[u8]) -> Result<(usize, usize), DecodeError> {
    let mut value = 0usize;
    let mut shift = 0u32;
    let mut consumed = 0usize;
    loop {
        let byte = *bytes.get(consumed).ok_or(DecodeError::UnexpectedEof {
            needed: 1,
            remaining: 0,
        })?;
        consumed += 1;
        value |= ((byte & 0x7F) as usize) << shift;
        if byte < 0x80 {
            // A continuation that contributed nothing means a shorter
            // encoding of this value exists.
            if byte == 0 && shift != 0 {
                return Err(DecodeError::NonMinimalLength);
            }
            return Ok((value, consumed));
        }
        shift += 7;
        if shift >= 28 {
            return Err(DecodeError::LengthTooLarge);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_LENGTH, encode, read};
    use crate::error::{DecodeError, EncodeError};

    fn encoded(value: usize) -> Vec<u8> {
        let (bytes, len) = encode(value).unwrap();
        bytes[..len].to_vec()
    }

    #[test]
    fn round_trips_across_width_boundaries() {
        for value in [
            0, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, MAX_LENGTH,
        ] {
            let bytes = encoded(value);
            assert_eq!(read(&bytes).unwrap(), (value, bytes.len()));
        }
    }

    #[test]
    fn width_grows_only_at_seven_bit_boundaries() {
        assert_eq!(encoded(0).len(), 1);
        assert_eq!(encoded(127).len(), 1);
        assert_eq!(encoded(128).len(), 2);
        assert_eq!(encoded(16_383).len(), 2);
        assert_eq!(encoded(16_384).len(), 3);
        assert_eq!(encoded(MAX_LENGTH).len(), 4);
    }

    #[test]
    fn rejects_a_redundant_continuation() {
        // 1, written in two bytes instead of one.
        assert_eq!(read(&[0x81, 0x00]), Err(DecodeError::NonMinimalLength));
        // 0, written in two bytes.
        assert_eq!(read(&[0x80, 0x00]), Err(DecodeError::NonMinimalLength));
        // 0, written in four.
        assert_eq!(
            read(&[0x80, 0x80, 0x80, 0x00]),
            Err(DecodeError::NonMinimalLength)
        );
    }

    #[test]
    fn rejects_a_field_past_four_bytes() {
        assert_eq!(
            read(&[0x80, 0x80, 0x80, 0x80, 0x01]),
            Err(DecodeError::LengthTooLarge)
        );
    }

    #[test]
    fn rejects_a_truncated_field() {
        assert!(matches!(
            read(&[0x80]),
            Err(DecodeError::UnexpectedEof { .. })
        ));
        assert!(matches!(read(&[]), Err(DecodeError::UnexpectedEof { .. })));
    }

    #[test]
    fn refuses_to_write_past_the_maximum() {
        assert_eq!(
            encode(MAX_LENGTH + 1).map(|_| ()),
            Err(EncodeError::LengthTooLarge {
                actual: MAX_LENGTH + 1,
                max: MAX_LENGTH,
            })
        );
    }

    /// The property the mutation harness relies on: exactly one byte string
    /// per length, so no two readable fields agree on a value.
    #[test]
    fn every_readable_field_re_encodes_to_itself() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let input = [a, b];
                if let Ok((value, consumed)) = read(&input) {
                    assert_eq!(encoded(value), input[..consumed]);
                }
            }
        }
    }
}
