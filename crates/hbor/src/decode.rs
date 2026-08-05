//! The decoder: bytes to values, or a rejection.
//!
//! The decoder is where canonicity is constructed rather than conventioned.
//! Every read that could admit two byte strings for one value rejects the
//! second: non-minimal lengths, booleans outside `{0, 1}`, unsorted map
//! keys, and bytes trailing a complete value.

use crate::error::DecodeError;
use crate::{HborDecode, varint};

/// Reads values from a byte string, refusing anything non-canonical.
///
/// Nesting is capped at construction. A consumer with its own depth bound
/// passes it here, and that bound is then the only one in play — a value
/// this decoder admits cannot trip the consumer's check afterwards.
pub struct Decoder<'a> {
    input: &'a [u8],
    cursor: usize,
    depth: usize,
    max_depth: usize,
}

impl<'a> Decoder<'a> {
    /// Build a decoder over `input` with the given nesting cap.
    #[must_use]
    pub const fn new(input: &'a [u8], max_depth: usize) -> Self {
        Self {
            input,
            cursor: 0,
            depth: 0,
            max_depth,
        }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len() - self.cursor
    }

    /// Read one byte.
    ///
    /// # Errors
    ///
    /// [`DecodeError::UnexpectedEof`] at the end of input.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let byte = *self
            .input
            .get(self.cursor)
            .ok_or(DecodeError::UnexpectedEof {
                needed: 1,
                remaining: 0,
            })?;
        self.cursor += 1;
        Ok(byte)
    }

    /// Borrow the next `len` bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::UnexpectedEof`] when fewer than `len` bytes remain.
    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < len {
            return Err(DecodeError::UnexpectedEof {
                needed: len,
                remaining: self.remaining(),
            });
        }
        let slice = &self.input[self.cursor..self.cursor + len];
        self.cursor += len;
        Ok(slice)
    }

    /// Read a fixed-width payload into an array.
    ///
    /// # Errors
    ///
    /// [`DecodeError::UnexpectedEof`] when fewer than `N` bytes remain.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.read_slice(N)?);
        Ok(out)
    }

    /// Read a length field, rejecting a claim the remaining input cannot
    /// satisfy.
    ///
    /// `min_element_len` is the smallest number of bytes one element can
    /// occupy. A sequence longer than `remaining / min_element_len` cannot
    /// exist in the bytes that are left, so rejecting here bounds every
    /// allocation by the input size — without the field having to declare a
    /// cap of its own.
    ///
    /// A `min_element_len` of zero admits any length the input can reach,
    /// since a zero-width element places no constraint.
    ///
    /// # Errors
    ///
    /// [`DecodeError::NonMinimalLength`] for a redundant encoding,
    /// [`DecodeError::LengthTooLarge`] past four bytes, and
    /// [`DecodeError::LengthExceedsInput`] for an unsatisfiable claim.
    pub fn read_len(&mut self, min_element_len: usize) -> Result<usize, DecodeError> {
        let (value, consumed) = varint::read(&self.input[self.cursor..])?;
        self.cursor += consumed;
        let capacity = self
            .remaining()
            .checked_div(min_element_len)
            .unwrap_or_else(|| self.remaining());
        if value > capacity {
            return Err(DecodeError::LengthExceedsInput {
                claimed: value,
                capacity,
            });
        }
        Ok(value)
    }

    /// Run `read` one level down, refusing to descend past the cap.
    ///
    /// Every nested value goes through here, whether it is read by its own
    /// [`HborDecode`] impl or by a bounded helper. Two spellings of the same
    /// wire format must charge the same depth, or a payload's acceptance
    /// would depend on how the type that reads it was written.
    ///
    /// # Errors
    ///
    /// [`DecodeError::DepthExceeded`] at the cap, or whatever `read` returns.
    pub fn descend<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        if self.depth >= self.max_depth {
            return Err(DecodeError::DepthExceeded {
                max: self.max_depth,
            });
        }
        self.depth += 1;
        let result = read(self);
        self.depth -= 1;
        result
    }

    /// Decode a nested value, one level down.
    ///
    /// # Errors
    ///
    /// [`DecodeError::DepthExceeded`] at the cap, or whatever `T` returns.
    pub fn nested<T: HborDecode>(&mut self) -> Result<T, DecodeError> {
        self.descend(T::decode)
    }

    /// Assert the input is exhausted.
    ///
    /// # Errors
    ///
    /// [`DecodeError::TrailingBytes`] when bytes follow the value. Trailing
    /// bytes would give one value two encodings, so they are a rejection
    /// rather than a value the caller may ignore.
    pub const fn finish(&self) -> Result<(), DecodeError> {
        if self.remaining() > 0 {
            return Err(DecodeError::TrailingBytes {
                remaining: self.remaining(),
            });
        }
        Ok(())
    }
}
