//! Impls for the scalar types and fixed-width arrays.
//!
//! Every scalar here is fixed width: the schema fixes how many bytes to
//! read, so nothing on the wire describes it. Integers are little-endian.
//! Floats have no impl and never will — no bit pattern of a float is a
//! meaning every node agrees on.
//!
//! `usize` and `isize` have no impl either. A field that would use one
//! names a width instead, so the encoding does not vary with the host that
//! produced it.

use core::mem::size_of;

use crate::decode::Decoder;
use crate::encode::Encoder;
use crate::error::{DecodeError, EncodeError};
use crate::{HborDecode, HborEncode, HborWidth};

macro_rules! fixed_width_integer {
    ($($ty:ty),* $(,)?) => { $(
        impl HborWidth for $ty {
            const MIN_ENCODED_LEN: usize = size_of::<$ty>();
        }

        impl HborEncode for $ty {
            fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
                encoder.write_fixed(&self.to_le_bytes());
                Ok(())
            }
        }

        impl HborDecode for $ty {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok(Self::from_le_bytes(decoder.read_array()?))
            }
        }
    )* };
}

fixed_width_integer!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl HborWidth for bool {
    const MIN_ENCODED_LEN: usize = 1;
}

impl HborEncode for bool {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_u8(u8::from(*self));
        Ok(())
    }
}

impl HborDecode for bool {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        // Every byte outside {0, 1} is a rejection, not a truthy value:
        // folding them onto `true` would give one value 255 encodings.
        match decoder.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(DecodeError::InvalidBool(other)),
        }
    }
}

// Zero width is truthful for unit: at fixed arity it contributes nothing
// and costs nothing. Sequence positions refuse it, in `collection`.
impl HborWidth for () {
    const MIN_ENCODED_LEN: usize = 0;
}

impl HborEncode for () {
    fn encode(&self, _encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        Ok(())
    }
}

impl HborDecode for () {
    fn decode(_decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(())
    }
}

impl<T> HborWidth for Option<T> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<T: HborEncode> HborEncode for Option<T> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        match self {
            Self::None => {
                encoder.write_u8(0);
                Ok(())
            }
            Self::Some(value) => {
                encoder.write_u8(1);
                encoder.nested(value)
            }
        }
    }
}

impl<T: HborDecode> HborDecode for Option<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match decoder.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(decoder.nested()?)),
            other => Err(DecodeError::InvalidDiscriminant(other)),
        }
    }
}

// Byte arrays only. Hashes, keys, signatures, and addresses are the whole
// population of fixed-size arrays in this protocol, and a generic `[T; N]`
// would have to build each value through a heap collection to stay safe —
// paying an allocation on the hottest decode path in the system to serve a
// case that does not occur. A generic impl is additive if one ever does.
impl<const N: usize> HborWidth for [u8; N] {
    const MIN_ENCODED_LEN: usize = N;
}

impl<const N: usize> HborEncode for [u8; N] {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_fixed(self);
        Ok(())
    }
}

impl<const N: usize> HborDecode for [u8; N] {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_array()
    }
}

macro_rules! tuple {
    ($($name:ident),+) => {
        impl<$($name: HborWidth),+> HborWidth for ($($name,)+) {
            const MIN_ENCODED_LEN: usize = 0 $(+ $name::MIN_ENCODED_LEN)+;
        }

        impl<$($name: HborEncode),+> HborEncode for ($($name,)+) {
            fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
                #[allow(non_snake_case)] // bindings mirror the type parameters
                let ($($name,)+) = self;
                $(encoder.nested($name)?;)+
                Ok(())
            }
        }

        impl<$($name: HborDecode),+> HborDecode for ($($name,)+) {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok(($(decoder.nested::<$name>()?,)+))
            }
        }
    };
}

tuple!(A, B);
tuple!(A, B, C);
tuple!(A, B, C, D);

#[cfg(test)]
mod tests {
    use crate::canonical::assert_canonical;
    use crate::error::DecodeError;
    use crate::{from_slice, to_vec};

    #[test]
    fn integers_are_fixed_width_little_endian() {
        assert_eq!(to_vec(&1u8).unwrap(), vec![1]);
        assert_eq!(to_vec(&1u16).unwrap(), vec![1, 0]);
        assert_eq!(to_vec(&1u32).unwrap(), vec![1, 0, 0, 0]);
        assert_eq!(to_vec(&(-1i32)).unwrap(), vec![0xFF; 4]);
        assert_eq!(to_vec(&1u128).unwrap().len(), 16);
    }

    #[test]
    fn a_byte_array_carries_no_length() {
        assert_eq!(to_vec(&[7u8; 32]).unwrap(), vec![7u8; 32]);
    }

    #[test]
    fn a_non_boolean_byte_rejects() {
        assert_eq!(from_slice::<bool>(&[2]), Err(DecodeError::InvalidBool(2)));
        assert_eq!(
            from_slice::<bool>(&[255]),
            Err(DecodeError::InvalidBool(255))
        );
    }

    #[test]
    fn a_non_option_tag_rejects() {
        assert_eq!(
            from_slice::<Option<u8>>(&[2, 0]),
            Err(DecodeError::InvalidDiscriminant(2))
        );
    }

    #[test]
    fn scalars_are_canonical() {
        assert_canonical(&0u8);
        assert_canonical(&u64::MAX);
        assert_canonical(&(-1i64));
        assert_canonical(&true);
        assert_canonical(&false);
        assert_canonical(&());
        assert_canonical(&[3u8; 16]);
        assert_canonical(&Option::<u32>::None);
        assert_canonical(&Some(9u32));
        assert_canonical(&(1u8, 2u16, 3u32));
    }
}
