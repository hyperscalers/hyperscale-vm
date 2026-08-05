//! HBOR — the canonical binary encoding.
//!
//! One byte string per value, one value per byte string. The encoding is
//! schema-external: the type is the schema, and the bytes carry only
//! content. There are no kind tags, no field names, and no way to skip a
//! field you do not know — a decoder without the type decodes nothing, which
//! is the trade that buys both the size and the single representation of
//! what a type means.
//!
//! # Canonicity
//!
//! If [`from_slice`] succeeds, [`to_vec`] of its result returns the input
//! bytes. This is constructed in the decoder rather than promised by the
//! encoder: a length with a redundant continuation byte, a boolean outside
//! `{0, 1}`, a map whose keys are not ascending, and bytes trailing a
//! complete value are all rejections. A signature or merkle root over an
//! HBOR payload therefore covers the value, not one of the value's spellings.
//!
//! [`canonical::assert_canonical`] is how a type proves it. Every impl in
//! this crate is checked by it, and consumers are expected to check theirs.
//!
//! # Bounds
//!
//! A collection's length is validated against the input that remains before
//! anything is allocated: a sequence of `T` cannot be longer than the
//! remaining bytes divided by [`HborDecode::MIN_ENCODED_LEN`]. Decoding `n`
//! bytes therefore allocates `O(n)`, whatever the payload claims, with no
//! per-field annotation. Protocol caps are a separate concern layered above
//! this one.
//!
//! # Shape
//!
//! A struct is its fields in declaration order, with nothing between them.
//! An enum is a one-byte discriminant then the variant's fields. `Option<T>`
//! is `0`, or `1` followed by the payload. Sequences, strings, maps, and
//! sets carry a minimal LEB128 length then their elements; every other type
//! is fixed width and carries no length at all. Integers are little-endian.
//!
//! Self-description, where a consumer needs it, is an envelope around a
//! payload — a schema hash beside the bytes — never a tag inside one.

pub mod bounded;
pub mod canonical;
pub mod decode;
pub mod encode;
pub mod error;
pub mod varint;

mod collection;
mod primitive;

pub use canonical::{assert_canonical, assert_canonical_at_depth};
pub use decode::Decoder;
pub use encode::Encoder;
pub use error::{DecodeError, EncodeError};
pub use hyperscale_hbor_macros::Hbor;
pub use varint::MAX_LENGTH;

/// The nesting cap [`to_vec`] and [`from_slice`] apply.
///
/// A consumer whose own value model bounds nesting more tightly passes that
/// bound to [`from_slice_with_depth`] instead, which makes the rejection
/// happen at decode rather than in a pass afterwards.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// A type with a canonical byte form.
pub trait HborEncode {
    /// Write this value's payload.
    ///
    /// Implementations write content only — the caller has already placed
    /// whatever discriminant or length the containing type owes.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] when a length is inexpressible, a declared bound is
    /// exceeded, or nesting reaches the encoder's cap.
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError>;
}

/// A type reconstructible from its canonical byte form.
pub trait HborDecode: Sized {
    /// The fewest bytes any value of this type can occupy.
    ///
    /// Containers divide the remaining input by this to bound a claimed
    /// length before allocating, so an understated value weakens that bound
    /// and an overstated one rejects payloads that are in fact valid. For a
    /// fixed-width type it is the width; for anything carrying a length
    /// field it is the encoding of the empty value.
    const MIN_ENCODED_LEN: usize;

    /// Read one value, rejecting any byte string that is not its canonical
    /// form.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for a malformed, non-canonical, or truncated payload.
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;
}

/// Encode `value` at [`DEFAULT_MAX_DEPTH`].
///
/// # Errors
///
/// [`EncodeError`], as [`HborEncode::encode`].
pub fn to_vec<T: HborEncode + ?Sized>(value: &T) -> Result<Vec<u8>, EncodeError> {
    to_vec_with_depth(value, DEFAULT_MAX_DEPTH)
}

/// Encode `value` against a specific nesting cap.
///
/// # Errors
///
/// [`EncodeError`], as [`HborEncode::encode`].
pub fn to_vec_with_depth<T: HborEncode + ?Sized>(
    value: &T,
    max_depth: usize,
) -> Result<Vec<u8>, EncodeError> {
    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf, max_depth);
    value.encode(&mut encoder)?;
    Ok(buf)
}

/// Decode one complete value from `bytes` at [`DEFAULT_MAX_DEPTH`].
///
/// # Errors
///
/// [`DecodeError`], including [`DecodeError::TrailingBytes`] when the value
/// does not consume the whole input.
pub fn from_slice<T: HborDecode>(bytes: &[u8]) -> Result<T, DecodeError> {
    from_slice_with_depth(bytes, DEFAULT_MAX_DEPTH)
}

/// Decode one complete value against a specific nesting cap.
///
/// A consumer that bounds nesting itself passes its own bound here. The
/// decoder then rejects a too-deep payload while reading it, so the value
/// the consumer receives cannot fail that check afterwards.
///
/// # Errors
///
/// [`DecodeError`], including [`DecodeError::TrailingBytes`] when the value
/// does not consume the whole input.
pub fn from_slice_with_depth<T: HborDecode>(
    bytes: &[u8],
    max_depth: usize,
) -> Result<T, DecodeError> {
    let mut decoder = Decoder::new(bytes, max_depth);
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{DecodeError, EncodeError, from_slice, from_slice_with_depth, to_vec_with_depth};

    #[test]
    fn trailing_bytes_reject() {
        assert_eq!(
            from_slice::<u8>(&[1, 2]),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn nesting_past_the_cap_rejects_on_both_sides() {
        // Four `Vec` levels around one byte, at a cap of three.
        let value = vec![vec![vec![vec![1u8]]]];
        assert!(matches!(
            to_vec_with_depth(&value, 3),
            Err(EncodeError::DepthExceeded { max: 3 })
        ));

        let bytes = to_vec_with_depth(&value, 8).unwrap();
        assert!(matches!(
            from_slice_with_depth::<Vec<Vec<Vec<Vec<u8>>>>>(&bytes, 3),
            Err(DecodeError::DepthExceeded { max: 3 })
        ));
        assert!(from_slice_with_depth::<Vec<Vec<Vec<Vec<u8>>>>>(&bytes, 8).is_ok());
    }

    /// A consumer's own nesting bound becomes the decoder's, so a payload it
    /// would reject never reaches it as a value.
    #[test]
    fn a_tighter_consumer_bound_rejects_at_decode() {
        let deep = vec![vec![vec![1u8]]];
        let bytes = to_vec_with_depth(&deep, 8).unwrap();
        assert!(from_slice_with_depth::<Vec<Vec<Vec<u8>>>>(&bytes, 2).is_err());
    }
}
