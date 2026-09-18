//! Collections that carry their cap in the type.
//!
//! A protocol bound on a length is a fact about a type, not about the field
//! that happens to hold it: `Capped<Vec<Address>, 16>` is a list of at most
//! sixteen addresses wherever it is written, through any alias or wrapper,
//! and no second spelling of the figure exists for a field to disagree
//! with. The cap is held at construction — a value past it cannot be built
//! — so the encoder has nothing to refuse, and the decoder refuses a claimed
//! length past it before anything is allocated.
//!
//! Three types, because two runs have elements that are not shaped types:
//! [`Bytes`] is a byte string written in one copy, and [`Text`] is UTF-8
//! whose cap is bytes rather than characters, which is what the encoding
//! bounds. [`Capped`] is generic over the element collections.
//!
//! None of the three derefs mutably. A mutable deref would move the cap
//! from the constructor to the encoder, and a cap the encoder is the first
//! to enforce is an error arm every writer has to carry. The writers are
//! the constructors and the fallible inserts here.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use crate::decode::Decoder;
use crate::encode::{Encoder, Sink};
use crate::error::{DecodeError, EncodeError};
use crate::shape::{HborShape, ShapeRegistry, TypeShape};
use crate::varint::MAX_LENGTH;
use crate::{HborDecode, HborEncode, HborWidth, bounded};

/// A value past the cap its type states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{actual} past the cap of {max}")]
pub struct Overflow {
    /// The length the value would have had.
    pub actual: usize,
    /// The cap the type states.
    pub max: usize,
}

const fn within(actual: usize, max: usize) -> Result<(), Overflow> {
    if actual > max {
        return Err(Overflow { actual, max });
    }
    Ok(())
}

/// A cap has to be a length the wire can carry, or no value of the type
/// could ever be written.
macro_rules! expressible {
    ($cap:expr) => {
        const {
            assert!(
                $cap <= MAX_LENGTH,
                "a cap past the largest expressible length can never be met"
            );
        }
    };
}

mod sealed {
    pub trait Sealed {}
}

/// A collection [`Capped`] may hold: one with a length, and a read that
/// refuses a claimed length past a cap before allocating for it.
pub trait Collection: sealed::Sealed + Sized {
    /// How many elements the value holds.
    fn length(&self) -> usize;
    /// Read a value of at most `max` elements.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BoundExceeded`] past `max`, or whatever the elements
    /// fail with.
    fn decode_capped(decoder: &mut Decoder<'_>, max: usize) -> Result<Self, DecodeError>;
}

impl<T> sealed::Sealed for Vec<T> {}

impl<T: HborDecode> Collection for Vec<T> {
    fn length(&self) -> usize {
        self.len()
    }

    fn decode_capped(decoder: &mut Decoder<'_>, max: usize) -> Result<Self, DecodeError> {
        bounded::decode_bounded_vec(decoder, max)
    }
}

impl<T> sealed::Sealed for BTreeSet<T> {}

impl<T: HborDecode + Ord> Collection for BTreeSet<T> {
    fn length(&self) -> usize {
        self.len()
    }

    fn decode_capped(decoder: &mut Decoder<'_>, max: usize) -> Result<Self, DecodeError> {
        bounded::decode_bounded_btree_set(decoder, max)
    }
}

impl<K, V> sealed::Sealed for BTreeMap<K, V> {}

impl<K: HborDecode + Ord, V: HborDecode> Collection for BTreeMap<K, V> {
    fn length(&self) -> usize {
        self.len()
    }

    fn decode_capped(decoder: &mut Decoder<'_>, max: usize) -> Result<Self, DecodeError> {
        bounded::decode_bounded_btree_map(decoder, max)
    }
}

/// A collection of at most `N` elements.
///
/// Encodes exactly as the collection it holds; what the type adds is the
/// cap, held at construction and checked at decode.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capped<C, const N: usize>(C);

impl<C: Collection, const N: usize> Capped<C, N> {
    /// The most elements a value may hold.
    pub const MAX: usize = N;

    /// `collection`, where it fits the cap.
    ///
    /// # Errors
    ///
    /// [`Overflow`] past `N`.
    pub fn new(collection: C) -> Result<Self, Overflow> {
        within(collection.length(), N)?;
        Ok(Self(collection))
    }

    /// The collection, out from under its cap.
    pub fn into_inner(self) -> C {
        self.0
    }
}

impl<T, const N: usize> Capped<Vec<T>, N> {
    /// The empty list.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Append `item`, where the cap has room for it.
    ///
    /// # Errors
    ///
    /// [`Overflow`] where the list is already at `N`.
    pub fn push(&mut self, item: T) -> Result<(), Overflow> {
        within(self.0.len() + 1, N)?;
        self.0.push(item);
        Ok(())
    }
}

impl<T: Ord, const N: usize> Capped<BTreeSet<T>, N> {
    /// The empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Insert `item`, where the cap has room for a new member.
    ///
    /// # Errors
    ///
    /// [`Overflow`] where `item` is new and the set is already at `N`.
    pub fn insert(&mut self, item: T) -> Result<bool, Overflow> {
        if self.0.contains(&item) {
            return Ok(false);
        }
        within(self.0.len() + 1, N)?;
        Ok(self.0.insert(item))
    }
}

impl<K: Ord, V, const N: usize> Capped<BTreeMap<K, V>, N> {
    /// The empty map.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// Insert `value` at `key`, where the cap has room for a new key.
    ///
    /// # Errors
    ///
    /// [`Overflow`] where `key` is new and the map is already at `N`.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, Overflow> {
        if !self.0.contains_key(&key) {
            within(self.0.len() + 1, N)?;
        }
        Ok(self.0.insert(key, value))
    }
}

impl<C, const N: usize> Deref for Capped<C, N> {
    type Target = C;

    fn deref(&self) -> &C {
        &self.0
    }
}

impl<T: HborDecode, const N: usize> TryFrom<Vec<T>> for Capped<Vec<T>, N> {
    type Error = Overflow;

    fn try_from(list: Vec<T>) -> Result<Self, Overflow> {
        Self::new(list)
    }
}

impl<T: HborDecode + Ord, const N: usize> TryFrom<BTreeSet<T>> for Capped<BTreeSet<T>, N> {
    type Error = Overflow;

    fn try_from(set: BTreeSet<T>) -> Result<Self, Overflow> {
        Self::new(set)
    }
}

impl<K: HborDecode + Ord, V: HborDecode, const N: usize> TryFrom<BTreeMap<K, V>>
    for Capped<BTreeMap<K, V>, N>
{
    type Error = Overflow;

    fn try_from(map: BTreeMap<K, V>) -> Result<Self, Overflow> {
        Self::new(map)
    }
}

impl<C, const N: usize> HborWidth for Capped<C, N> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<C: Collection + HborEncode, const N: usize> HborEncode for Capped<C, N> {
    fn encode<S: Sink>(&self, encoder: &mut Encoder<S>) -> Result<(), EncodeError> {
        expressible!(N);
        self.0.encode(encoder)
    }
}

impl<C: Collection, const N: usize> HborDecode for Capped<C, N> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        expressible!(N);
        C::decode_capped(decoder, N).map(Self)
    }
}

impl<T: HborShape, const N: usize> HborShape for Capped<Vec<T>, N> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Seq(Box::new(T::shape(types)))
    }
}

impl<T: HborShape, const N: usize> HborShape for Capped<BTreeSet<T>, N> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Set(Box::new(T::shape(types)))
    }
}

impl<K: HborShape, V: HborShape, const N: usize> HborShape for Capped<BTreeMap<K, V>, N> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Map {
            key: Box::new(K::shape(types)),
            value: Box::new(V::shape(types)),
        }
    }
}

/// A byte string of at most `N` bytes.
///
/// Encodes as `Vec<u8>` does — a length then the bytes — in one copy each
/// way, which is the path a generic element loop cannot take.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes<const N: usize>(Vec<u8>);

impl<const N: usize> Bytes<N> {
    /// The most bytes a value may hold.
    pub const MAX: usize = N;

    /// `bytes`, where they fit the cap.
    ///
    /// # Errors
    ///
    /// [`Overflow`] past `N`.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Overflow> {
        within(bytes.len(), N)?;
        Ok(Self(bytes))
    }

    /// No bytes.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// The bytes, out from under their cap.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<const N: usize> Deref for Bytes<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for Bytes<N> {
    type Error = Overflow;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Overflow> {
        Self::new(bytes)
    }
}

impl<const N: usize> TryFrom<&[u8]> for Bytes<N> {
    type Error = Overflow;

    fn try_from(bytes: &[u8]) -> Result<Self, Overflow> {
        Self::new(bytes.to_vec())
    }
}

impl<const N: usize> HborWidth for Bytes<N> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<const N: usize> HborEncode for Bytes<N> {
    fn encode<S: Sink>(&self, encoder: &mut Encoder<S>) -> Result<(), EncodeError> {
        expressible!(N);
        bounded::encode_bytes(encoder, &self.0)
    }
}

impl<const N: usize> HborDecode for Bytes<N> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        expressible!(N);
        bounded::decode_bounded_bytes(decoder, N).map(Self)
    }
}

impl<const N: usize> HborShape for Bytes<N> {
    fn shape(_: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Seq(Box::new(TypeShape::U8))
    }
}

/// UTF-8 text of at most `N` bytes.
///
/// The cap counts bytes, not characters: it bounds the wire, and a
/// character count would not. Nothing normalizes the text — two byte
/// strings that look alike are two values.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text<const N: usize>(String);

impl<const N: usize> Text<N> {
    /// The most bytes a value may hold.
    pub const MAX: usize = N;

    /// `text`, where it fits the cap.
    ///
    /// # Errors
    ///
    /// [`Overflow`] past `N` bytes.
    pub fn new(text: String) -> Result<Self, Overflow> {
        within(text.len(), N)?;
        Ok(Self(text))
    }

    /// The empty text.
    #[must_use]
    pub const fn empty() -> Self {
        Self(String::new())
    }

    /// The text, out from under its cap.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<const N: usize> Deref for Text<N> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> TryFrom<String> for Text<N> {
    type Error = Overflow;

    fn try_from(text: String) -> Result<Self, Overflow> {
        Self::new(text)
    }
}

impl<const N: usize> TryFrom<&str> for Text<N> {
    type Error = Overflow;

    fn try_from(text: &str) -> Result<Self, Overflow> {
        Self::new(text.to_owned())
    }
}

impl<const N: usize> HborWidth for Text<N> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<const N: usize> HborEncode for Text<N> {
    fn encode<S: Sink>(&self, encoder: &mut Encoder<S>) -> Result<(), EncodeError> {
        expressible!(N);
        encoder.write_sized(self.0.as_bytes())
    }
}

impl<const N: usize> HborDecode for Text<N> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        expressible!(N);
        bounded::decode_bounded_string(decoder, N).map(Self)
    }
}

impl<const N: usize> HborShape for Text<N> {
    fn shape(_: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Text
    }
}
