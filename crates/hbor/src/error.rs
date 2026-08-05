//! Encode and decode failure vocabularies.
//!
//! Decode errors name what the byte string did wrong rather than what the
//! decoder wanted, because a peer sees the verdict and every node must reach
//! the same one. Every variant is a deterministic function of the input.

use thiserror::Error;

/// Why a value could not be encoded.
///
/// Encoding a value built through its type's own constructors does not fail.
/// These variants catch values assembled past a bound the type declares —
/// a collection grown past its cap, a graph nested past the depth its
/// decoder would admit — so the encoder refuses to produce bytes no decoder
/// would accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EncodeError {
    /// A length exceeded what the four-byte length field can express.
    #[error("length {actual} exceeds the encodable maximum {max}")]
    LengthTooLarge {
        /// The rejected length.
        actual: usize,
        /// The largest expressible length.
        max: usize,
    },

    /// A field exceeded the bound its type declares.
    #[error("{field}: {actual} exceeds the declared bound {max}")]
    BoundExceeded {
        /// The field's name.
        field: &'static str,
        /// The value's actual length.
        actual: usize,
        /// The declared bound.
        max: usize,
    },

    /// The value nests deeper than the encoder's cap.
    #[error("value nests deeper than {max}")]
    DepthExceeded {
        /// The cap that was reached.
        max: usize,
    },
}

/// Why a byte string is not a valid encoding of the requested type.
///
/// Canonicity failures — a non-minimal length, unsorted keys, a boolean
/// outside `{0, 1}` — are rejections, not normalizations. A decoder that
/// repaired them would admit two byte strings for one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// The input ended while a field was still being read.
    #[error("unexpected end of input: needed {needed} more bytes, {remaining} remain")]
    UnexpectedEof {
        /// Bytes the field still required.
        needed: usize,
        /// Bytes actually left.
        remaining: usize,
    },

    /// The value decoded, but bytes followed it.
    #[error("{remaining} trailing bytes after a complete value")]
    TrailingBytes {
        /// Bytes left after the value.
        remaining: usize,
    },

    /// A length used more bytes than its value requires.
    #[error("non-minimal length encoding")]
    NonMinimalLength,

    /// A length field ran past four bytes.
    #[error("length field exceeds four bytes")]
    LengthTooLarge,

    /// A claimed length could not be satisfied by the bytes that remain.
    ///
    /// The bound is derived from the input rather than declared: a sequence
    /// of `T` cannot be longer than the remaining input divided by `T`'s
    /// minimum encoded length. Rejecting here is what keeps a peer-claimed
    /// length from driving an allocation it has not paid for in bytes.
    #[error("claimed length {claimed} exceeds the {capacity} the remaining input can hold")]
    LengthExceedsInput {
        /// The length the input claimed.
        claimed: usize,
        /// The most the remaining bytes could encode.
        capacity: usize,
    },

    /// A collection exceeded the bound its type declares.
    #[error("{actual} elements exceeds the declared bound {max}")]
    BoundExceeded {
        /// The declared bound.
        max: usize,
        /// The length the input claimed.
        actual: usize,
    },

    /// The value nests deeper than the decoder's cap.
    #[error("value nests deeper than {max}")]
    DepthExceeded {
        /// The cap that was reached.
        max: usize,
    },

    /// A boolean byte was neither zero nor one.
    #[error("byte {0} is not a boolean")]
    InvalidBool(u8),

    /// A discriminant named no variant of the type.
    #[error("discriminant {0} names no variant")]
    InvalidDiscriminant(u8),

    /// A string field was not valid UTF-8.
    #[error("string field is not valid UTF-8")]
    InvalidUtf8,

    /// The type's own predicate rejected the decoded value.
    ///
    /// Cross-field invariants — a length that must match a count, a hash
    /// that must match what it covers — are checked here, at the wire
    /// boundary, once every field is in hand. The string names which
    /// predicate failed and is a fixed part of the type, so the verdict
    /// stays a deterministic function of the input.
    #[error("value rejected by its type's predicate: {0}")]
    FailedValidation(&'static str),

    /// Map or set entries arrived out of ascending key order.
    ///
    /// Ordered collections encode sorted, so unsorted input is a second
    /// byte string for a value that already has one.
    #[error("map or set entries are not in ascending key order")]
    UnsortedKeys,
}
