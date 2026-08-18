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
//! remaining bytes divided by [`HborWidth::MIN_ENCODED_LEN`], and the
//! reservation hint is capped by the bytes that remain besides, so an input
//! that will be rejected never holds a reservation larger than itself.
//! Decoding `n` bytes performs `O(n)` work and reserves `O(n)` bytes ahead
//! of element validation, with no per-field annotation.
//!
//! An accepted value's footprint is the value's own, and that can exceed its
//! encoding by a per-type constant — half a million one-byte empty vectors
//! decode into megabytes of `Vec` headers. The wire cannot bound that
//! constant; message-size limits and `#[hbor(max = N)]` caps are what do.
//!
//! Sequences over zero-width elements — `Vec<()>`, a set of unit markers —
//! are refused at compile time: their length is a count no input can pay
//! for, and the honest encoding of a count is the count.
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
//! Schema *derivation* — a describable shape a tool could walk — is
//! deliberately absent, not forgotten: the type is the schema, nothing on
//! the codec path depends on one, and an opt-in derive can land later
//! without touching what a payload means.

pub mod bounded;
pub mod canonical;
pub mod decode;
pub mod encode;
pub mod error;
pub mod varint;

pub mod hash;
pub mod merkle;
pub mod signing;

mod collection;
mod primitive;

pub use canonical::{assert_canonical, assert_canonical_at_depth};
pub use decode::Decoder;
pub use encode::{Encoder, Fixed, Sink};
pub use error::{DecodeError, EncodeError};
pub use hash::{Hash32, Hasher};
pub use hyperscale_hbor_macros::{Hbor, HborMerkle};
pub use merkle::Chunked;
pub use signing::{HborSigned, HborSignedWith};
pub use varint::MAX_LENGTH;

/// The nesting cap [`to_vec`] and [`from_slice`] apply.
///
/// A consumer whose own value model bounds nesting more tightly passes that
/// bound to [`from_slice_with_depth`] instead, which makes the rejection
/// happen at decode rather than in a pass afterwards.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// A type with a fixed lower bound on its encoded size.
///
/// The bound is a property of the wire form, shared by both directions:
/// containers divide the remaining input by an element's minimum to bound a
/// claimed length before allocating, and refuse element types with no
/// minimum at all — which is why the encoder needs the constant too, so a
/// sequence its own decoder cannot admit is unwritable rather than merely
/// unreadable.
pub trait HborWidth {
    /// The fewest bytes any value of this type can occupy.
    ///
    /// An understated value weakens the length bound; an overstated one
    /// rejects payloads that are in fact valid. For a fixed-width type it is
    /// the width; for anything carrying a length field it is the encoding of
    /// the empty value. Zero is truthful for `()` and unit structs, which
    /// compose freely at fixed arity — only a variable-length collection
    /// refuses them as elements, when the codec is instantiated:
    ///
    /// ```compile_fail
    /// // A sequence over zero-width elements is a count in disguise.
    /// let _ = hyperscale_hbor::to_vec(&vec![(), ()]);
    /// ```
    ///
    /// ```compile_fail
    /// // The decoder refuses the same instantiation.
    /// let _ = hyperscale_hbor::from_slice::<Vec<()>>(&[0]);
    /// ```
    const MIN_ENCODED_LEN: usize;
}

/// A type with a canonical byte form.
pub trait HborEncode: HborWidth {
    /// Write this value's payload.
    ///
    /// Implementations write content only — the caller has already placed
    /// whatever discriminant or length the containing type owes.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] when a length is inexpressible, a declared bound is
    /// exceeded, or nesting reaches the encoder's cap.
    fn encode<S: Sink>(&self, encoder: &mut Encoder<S>) -> Result<(), EncodeError>;
}

/// A type reconstructible from its canonical byte form.
pub trait HborDecode: HborWidth + Sized {
    /// Read one value, rejecting any byte string that is not its canonical
    /// form.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for a malformed, non-canonical, or truncated payload.
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;
}

/// A type whose encoding cannot fail.
///
/// Encoding fails three ways — a length past what the length field can
/// express, a declared [`max`](hyperscale_hbor_macros::Hbor) bound, and
/// nesting past the encoder's cap — and all three come from a length. A
/// type that carries none is fixed width end to end, so writing it down
/// is arithmetic on a buffer and there is nothing to refuse.
///
/// The point of saying so in the type system is that a caller can then
/// encode *without an error arm*. Where that matters is a contract method
/// marked total: a body that can fault cannot carry the mark, and a mark
/// that a panicking encoder took away would be a protocol property lost
/// to an implementation detail.
///
/// Granted by `#[derive(Hbor)]` to a struct or enum whose every field is
/// itself infallible, and by hand below to the fixed-width primitives.
/// A `Vec`, a `String`, a map or a set is not, and neither is anything
/// holding one — which is a bound the compiler reports rather than a
/// property anyone has to remember.
pub trait HborInfallible: HborEncode {
    /// The most bytes this type's encoding can occupy.
    ///
    /// A bound rather than a width, because `Option<T>` is one byte or
    /// one more than `T` — so a type holding one has no single length,
    /// and what a caller can size a buffer from is the larger.
    const MAX_ENCODED_LEN: usize;
}

/// Encode `value` into `out`, returning the bytes written.
///
/// Allocates nothing, so nothing here can fault: this is the path a
/// contract method marked total encodes on, where growing a heap buffer
/// would be a failure the totality scan reads as a trap.
///
/// The empty slice is unreachable for a buffer of at least
/// [`HborInfallible::MAX_ENCODED_LEN`] bytes — the bound is the statement
/// that the value fits and the encode has nothing to report. Written as a
/// fallback rather than an unwrap because an unwrap is a panic, and a
/// panic is what the whole path exists to avoid.
#[must_use]
pub fn to_slice_infallible<'b, T: HborInfallible + ?Sized>(
    value: &T,
    out: &'b mut [u8],
) -> &'b [u8] {
    let mut encoder = Encoder::new(Fixed::new(out), DEFAULT_MAX_DEPTH);
    let written = value
        .encode(&mut encoder)
        .ok()
        .and_then(|()| encoder.finish().written());
    written.and_then(|len| out.get(..len)).unwrap_or_default()
}

/// Encode `value`, which cannot fail.
///
/// The heap twin of [`to_slice_infallible`], for a caller with an
/// allocator it may use.
#[must_use]
pub fn to_vec_infallible<T: HborInfallible + ?Sized>(value: &T) -> Vec<u8> {
    to_vec(value).unwrap_or_default()
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
