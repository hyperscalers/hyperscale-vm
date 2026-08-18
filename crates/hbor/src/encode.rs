//! The encoder: values to bytes.

use crate::error::EncodeError;
use crate::varint;

/// Where an encoder puts the bytes it writes.
///
/// Two implementations, and the split is by *type* rather than by a
/// branch inside one. A branch would put both in the same function, and
/// the deploy-time totality scan walks the call graph rather than the
/// values flowing through it — so an encode that could only ever fill a
/// slice would still reach the growing arm, and reaching an allocation
/// is what costs a contract method its total mark.
pub trait Sink {
    /// Append `bytes`.
    fn write(&mut self, bytes: &[u8]);

    /// Append a payload whose width is known where it is written.
    ///
    /// Split from [`Sink::write`] because a constant width is what lets
    /// a fixed sink copy without a length check and without a byte loop.
    /// One of those refuses a total method for a panic it cannot reach,
    /// the other for a fuel cost nothing bounds.
    fn write_array<const N: usize>(&mut self, bytes: &[u8; N]) {
        self.write(bytes);
    }

    /// Bytes written so far.
    fn written(&self) -> usize;
}

impl Sink for &mut Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn written(&self) -> usize {
        self.len()
    }
}

/// A caller's own buffer, filled from the front and never grown.
///
/// Nothing here allocates, so nothing here can fault — which is the whole
/// point: this is the sink a guest encodes on when the method it is
/// running promised it cannot.
pub struct Fixed<'a> {
    buf: &'a mut [u8],
    at: usize,
    overflowed: bool,
}

impl<'a> Fixed<'a> {
    /// A sink filling `buf`.
    #[must_use]
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            at: 0,
            overflowed: false,
        }
    }

    /// What was written, or `None` if the value did not fit.
    ///
    /// Overflow is recorded rather than refused per write, so no write
    /// signature carries a failure and nothing on the path can panic.
    /// The caller reads it once; a buffer sized from the type's own
    /// bound can never set it.
    #[must_use]
    pub fn written(&self) -> Option<usize> {
        (!self.overflowed).then_some(self.at)
    }
}

impl Sink for Fixed<'_> {
    fn write(&mut self, bytes: &[u8]) {
        let slot = self
            .at
            .checked_add(bytes.len())
            .and_then(|end| self.buf.get_mut(self.at..end));
        if let Some(slot) = slot {
            slot.copy_from_slice(bytes);
            self.at += bytes.len();
        } else {
            self.overflowed = true;
        }
    }

    fn write_array<const N: usize>(&mut self, bytes: &[u8; N]) {
        // Indexing panics and the offset can overflow, so both are asked
        // rather than assumed; the copy is a fixed-size move, which needs
        // neither a length check nor a loop.
        let slot = self
            .at
            .checked_add(N)
            .and_then(|end| self.buf.get_mut(self.at..end))
            .and_then(|slot| <&mut [u8; N]>::try_from(slot).ok());
        if let Some(slot) = slot {
            *slot = *bytes;
            self.at += N;
        } else {
            self.overflowed = true;
        }
    }

    fn written(&self) -> usize {
        self.at
    }
}

/// Writes encoded values into a caller-supplied sink.
///
/// The sink is borrowed rather than owned so a caller can encode several
/// values into one allocation, or encode into a buffer it is about to hand
/// to storage.
///
/// Nesting is bounded: [`Encoder::nested`] refuses to descend past the cap,
/// so the encoder never produces bytes its own decoder would reject for
/// depth.
pub struct Encoder<S> {
    out: S,
    depth: usize,
    max_depth: usize,
}

impl<S: Sink> Encoder<S> {
    /// Build an encoder writing into `out` with the given nesting cap.
    pub const fn new(out: S, max_depth: usize) -> Self {
        Self {
            out,
            depth: 0,
            max_depth,
        }
    }

    /// The sink, back.
    pub fn finish(self) -> S {
        self.out
    }

    /// Append one byte.
    pub fn write_u8(&mut self, byte: u8) {
        self.out.write_array(&[byte]);
    }

    /// Append a fixed-width payload verbatim.
    ///
    /// The schema fixes the width, so nothing is written to describe it.
    pub fn write_fixed(&mut self, bytes: &[u8]) {
        self.out.write(bytes);
    }

    /// Append a payload whose width is a constant where it is written.
    pub fn write_array<const N: usize>(&mut self, bytes: &[u8; N]) {
        self.out.write_array(bytes);
    }

    /// Append a minimal length field.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthTooLarge`] past [`varint::MAX_LENGTH`].
    pub fn write_len(&mut self, len: usize) -> Result<(), EncodeError> {
        let (bytes, written) = varint::encode(len)?;
        if let Some(field) = bytes.get(..written) {
            self.write_fixed(field);
        }
        Ok(())
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

    /// Run `write` one level down, refusing to descend past the cap.
    ///
    /// The encoder's mirror of [`Decoder::descend`](crate::Decoder::descend):
    /// a value written through a direct helper charges the same depth as one
    /// written through its own impl, so the encoder cannot produce bytes its
    /// decoder would reject.
    ///
    /// # Errors
    ///
    /// [`EncodeError::DepthExceeded`] at the cap, or whatever `write`
    /// returns.
    pub fn descend(
        &mut self,
        write: impl FnOnce(&mut Self) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        if self.depth >= self.max_depth {
            return Err(EncodeError::DepthExceeded {
                max: self.max_depth,
            });
        }
        self.depth += 1;
        let result = write(self);
        self.depth -= 1;
        result
    }

    /// Encode a nested value, one level down.
    ///
    /// # Errors
    ///
    /// [`EncodeError::DepthExceeded`] at the cap, or whatever `value`
    /// returns.
    pub fn nested<T: super::HborEncode + ?Sized>(&mut self, value: &T) -> Result<(), EncodeError> {
        self.descend(|encoder| value.encode(encoder))
    }

    /// Bytes written so far.
    #[must_use]
    pub fn position(&self) -> usize {
        self.out.written()
    }
}
