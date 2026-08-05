//! The encoder: values to bytes.

use crate::error::EncodeError;
use crate::varint;

/// Writes encoded values into a caller-supplied buffer.
///
/// The buffer is borrowed rather than owned so a caller can encode several
/// values into one allocation, or encode into a buffer it is about to hand
/// to storage.
///
/// Nesting is bounded: [`Encoder::nested`] refuses to descend past the cap,
/// so the encoder never produces bytes its own decoder would reject for
/// depth.
pub struct Encoder<'a> {
    buf: &'a mut Vec<u8>,
    depth: usize,
    max_depth: usize,
}

impl<'a> Encoder<'a> {
    /// Build an encoder writing into `buf` with the given nesting cap.
    pub const fn new(buf: &'a mut Vec<u8>, max_depth: usize) -> Self {
        Self {
            buf,
            depth: 0,
            max_depth,
        }
    }

    /// Append one byte.
    pub fn write_u8(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    /// Append a fixed-width payload verbatim.
    ///
    /// The schema fixes the width, so nothing is written to describe it.
    pub fn write_fixed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Append a minimal length field.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthTooLarge`] past [`varint::MAX_LENGTH`].
    pub fn write_len(&mut self, len: usize) -> Result<(), EncodeError> {
        varint::write(self.buf, len)
    }

    /// Append a length field followed by the bytes it measures.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthTooLarge`] past [`varint::MAX_LENGTH`].
    pub fn write_sized(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.write_len(bytes.len())?;
        self.write_fixed(bytes);
        Ok(())
    }

    /// Encode a nested value, one level down.
    ///
    /// # Errors
    ///
    /// [`EncodeError::DepthExceeded`] at the cap, or whatever `value`
    /// returns.
    pub fn nested<T: super::HborEncode + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        if self.depth >= self.max_depth {
            return Err(EncodeError::DepthExceeded {
                max: self.max_depth,
            });
        }
        self.depth += 1;
        let result = value.encode(self);
        self.depth -= 1;
        result
    }

    /// Bytes written so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.buf.len()
    }
}
