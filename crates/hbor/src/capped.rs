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
//! the constructors and the fallible inserts here. What is offered mutably
//! is what cannot reach the cap: an element in place — an index, an
//! iterator, a map's value — since replacing one changes no length, and
//! removal, since a shorter value is under any cap the longer one met.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{Deref, Index, IndexMut};

use crate::decode::Decoder;
use crate::encode::{Encoder, Sink};
use crate::error::{DecodeError, EncodeError};
use crate::node::ShapeNode;
use crate::shape::HborShape;
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

/// A collection [`Capped`] may hold: one with a length.
pub trait Collection: sealed::Sealed + Sized {
    /// How many elements the value holds.
    fn length(&self) -> usize;
}

/// A collection with a read that refuses a claimed length past a cap
/// before allocating for it.
pub trait CappedDecode: Collection {
    /// Read a value of at most `max` elements.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BoundExceeded`] past `max`, or whatever the elements
    /// fail with.
    fn decode_capped(decoder: &mut Decoder<'_>, max: usize) -> Result<Self, DecodeError>;
}

impl<T> sealed::Sealed for Vec<T> {}

impl<T> Collection for Vec<T> {
    fn length(&self) -> usize {
        self.len()
    }
}

impl<T: HborDecode> CappedDecode for Vec<T> {
    fn decode_capped(decoder: &mut Decoder<'_>, max: usize) -> Result<Self, DecodeError> {
        bounded::decode_bounded_vec(decoder, max)
    }
}

impl<T> sealed::Sealed for BTreeSet<T> {}

impl<T> Collection for BTreeSet<T> {
    fn length(&self) -> usize {
        self.len()
    }
}

impl<T: HborDecode + Ord> CappedDecode for BTreeSet<T> {
    fn decode_capped(decoder: &mut Decoder<'_>, max: usize) -> Result<Self, DecodeError> {
        bounded::decode_bounded_btree_set(decoder, max)
    }
}

impl<K, V> sealed::Sealed for BTreeMap<K, V> {}

impl<K, V> Collection for BTreeMap<K, V> {
    fn length(&self) -> usize {
        self.len()
    }
}

impl<K: HborDecode + Ord, V: HborDecode> CappedDecode for BTreeMap<K, V> {
    fn decode_capped(decoder: &mut Decoder<'_>, max: usize) -> Result<Self, DecodeError> {
        bounded::decode_bounded_btree_map(decoder, max)
    }
}

/// A collection of at most `N` elements.
///
/// Encodes exactly as the collection it holds; what the type adds is the
/// cap, held at construction and checked at decode.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capped<C, const N: usize>(C);

/// Rendered as the collection it holds: the cap is the type's, and a
/// value's rendering is the value's.
impl<C: fmt::Debug, const N: usize> fmt::Debug for Capped<C, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

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

impl<C, const N: usize> Capped<C, N> {
    /// The elements, borrowed.
    pub fn iter<'a>(&'a self) -> <&'a C as IntoIterator>::IntoIter
    where
        &'a C: IntoIterator,
    {
        (&self.0).into_iter()
    }
}

impl<T, const N: usize> Capped<Vec<T>, N> {
    /// The empty list, as a constant; a set or a map starts from
    /// `Default`.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// The elements, mutably: an element replaced in place changes no
    /// length.
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }

    /// The element at `index`, mutably, where there is one.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.0.get_mut(index)
    }

    /// Every element through `map`, under the same cap: the length is
    /// kept, so the result cannot outgrow it.
    pub fn map<U>(&self, map: impl FnMut(&T) -> U) -> Capped<Vec<U>, N> {
        Capped(self.0.iter().map(map).collect())
    }

    /// Every element through `map`, under the same cap, or the first
    /// refusal `map` answers with.
    ///
    /// # Errors
    ///
    /// Whatever `map` refuses with.
    pub fn try_map<U, E>(
        &self,
        map: impl FnMut(&T) -> Result<U, E>,
    ) -> Result<Capped<Vec<U>, N>, E> {
        self.0.iter().map(map).collect::<Result<_, E>>().map(Capped)
    }

    /// Remove the last element, where there is one.
    pub fn pop(&mut self) -> Option<T> {
        self.0.pop()
    }

    /// Remove the element at `index`, closing the gap.
    ///
    /// # Panics
    ///
    /// As `Vec::remove`, past the end.
    pub fn remove(&mut self, index: usize) -> T {
        self.0.remove(index)
    }

    /// Exchange two elements in place.
    ///
    /// # Panics
    ///
    /// As `<[T]>::swap`, past the end.
    pub fn swap(&mut self, a: usize, b: usize) {
        self.0.swap(a, b);
    }

    /// Put the elements in `key` order, keeping the order of ties: a
    /// reordering changes no length.
    pub fn sort_by_key<K: Ord>(&mut self, key: impl FnMut(&T) -> K) {
        self.0.sort_by_key(key);
    }

    /// Keep the first `len` elements.
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    /// Keep the elements `keep` answers for.
    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.0.retain(keep);
    }

    /// Remove every element.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// A list written out, whose length the compiler holds under the cap.
    #[must_use]
    pub fn from_array<const M: usize>(items: [T; M]) -> Self {
        const {
            assert!(M <= N, "a list written past its cap");
        }
        Self(items.into())
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

    /// Insert `item` at `index`, shifting what follows, where the cap
    /// has room for it.
    ///
    /// # Errors
    ///
    /// [`Overflow`] where the list is already at `N`.
    ///
    /// # Panics
    ///
    /// As `Vec::insert`, past the end.
    pub fn insert(&mut self, index: usize, item: T) -> Result<(), Overflow> {
        within(self.0.len() + 1, N)?;
        self.0.insert(index, item);
        Ok(())
    }
}

impl<T: Ord, const N: usize> Capped<BTreeSet<T>, N> {
    /// A set written out, whose member count the compiler holds under
    /// the cap.
    #[must_use]
    pub fn from_members<const M: usize>(items: [T; M]) -> Self {
        const {
            assert!(M <= N, "a set written past its cap");
        }
        Self(BTreeSet::from(items))
    }

    /// Remove `item`, saying whether it was a member.
    pub fn remove(&mut self, item: &T) -> bool {
        self.0.remove(item)
    }

    /// Remove every member.
    pub fn clear(&mut self) {
        self.0.clear();
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
    /// Remove the entry at `key`, handing back its value where there was
    /// one.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.0.remove(key)
    }

    /// Remove every entry.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// The value at `key`, mutably, where there is one.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.0.get_mut(key)
    }

    /// The values, mutably: a value replaced in place changes no length.
    pub fn values_mut(&mut self) -> std::collections::btree_map::ValuesMut<'_, K, V> {
        self.0.values_mut()
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

impl<T, I, const N: usize> Index<I> for Capped<Vec<T>, N>
where
    Vec<T>: Index<I>,
{
    type Output = <Vec<T> as Index<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, I, const N: usize> IndexMut<I> for Capped<Vec<T>, N>
where
    Vec<T>: IndexMut<I>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut Capped<Vec<T>, N> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<T: PartialEq, const N: usize, const M: usize> PartialEq<[T; M]> for Capped<Vec<T>, N> {
    fn eq(&self, other: &[T; M]) -> bool {
        self.0 == other
    }
}

impl<T: PartialEq, const N: usize> PartialEq<[T]> for Capped<Vec<T>, N> {
    fn eq(&self, other: &[T]) -> bool {
        self.0 == other
    }
}

impl<T: PartialEq, const N: usize> PartialEq<Vec<T>> for Capped<Vec<T>, N> {
    fn eq(&self, other: &Vec<T>) -> bool {
        &self.0 == other
    }
}

impl<T, const N: usize> AsRef<[T]> for Capped<Vec<T>, N> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<C: IntoIterator, const N: usize> IntoIterator for Capped<C, N> {
    type Item = C::Item;
    type IntoIter = C::IntoIter;

    fn into_iter(self) -> C::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, C, const N: usize> IntoIterator for &'a Capped<C, N>
where
    &'a C: IntoIterator,
{
    type Item = <&'a C as IntoIterator>::Item;
    type IntoIter = <&'a C as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for Capped<Vec<T>, N> {
    type Error = Overflow;

    fn try_from(list: Vec<T>) -> Result<Self, Overflow> {
        Self::new(list)
    }
}

impl<T, const N: usize> TryFrom<BTreeSet<T>> for Capped<BTreeSet<T>, N> {
    type Error = Overflow;

    fn try_from(set: BTreeSet<T>) -> Result<Self, Overflow> {
        Self::new(set)
    }
}

impl<K, V, const N: usize> TryFrom<BTreeMap<K, V>> for Capped<BTreeMap<K, V>, N> {
    type Error = Overflow;

    fn try_from(map: BTreeMap<K, V>) -> Result<Self, Overflow> {
        Self::new(map)
    }
}

impl<C, const N: usize> HborWidth for Capped<C, N> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<C: HborEncode, const N: usize> HborEncode for Capped<C, N> {
    fn encode<S: Sink>(&self, encoder: &mut Encoder<S>) -> Result<(), EncodeError> {
        expressible!(N);
        self.0.encode(encoder)
    }
}

impl<C: CappedDecode, const N: usize> HborDecode for Capped<C, N> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        expressible!(N);
        C::decode_capped(decoder, N).map(Self)
    }
}

impl<T: HborShape, const N: usize> HborShape for Capped<Vec<T>, N> {
    const NODE: &'static ShapeNode = &ShapeNode::Seq {
        cap: N,
        element: T::NODE,
    };
}

impl<T: HborShape, const N: usize> HborShape for Capped<BTreeSet<T>, N> {
    const NODE: &'static ShapeNode = &ShapeNode::Set {
        cap: N,
        element: T::NODE,
    };
}

impl<K: HborShape, V: HborShape, const N: usize> HborShape for Capped<BTreeMap<K, V>, N> {
    const NODE: &'static ShapeNode = &ShapeNode::Map {
        cap: N,
        key: K::NODE,
        value: V::NODE,
    };
}

/// A byte string of at most `N` bytes.
///
/// Encodes as `Vec<u8>` does — a length then the bytes — in one copy each
/// way, which is the path a generic element loop cannot take.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes<const N: usize>(Vec<u8>);

impl<const N: usize> fmt::Debug for Bytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

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

    /// Bytes written out, whose length the compiler holds under the cap.
    #[must_use]
    pub fn from_array<const M: usize>(bytes: [u8; M]) -> Self {
        const {
            assert!(M <= N, "bytes written past their cap");
        }
        Self(bytes.into())
    }

    /// The bytes, out from under their cap.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// The bytes, borrowed one at a time.
    pub fn iter(&self) -> std::slice::Iter<'_, u8> {
        self.0.iter()
    }

    /// The bytes, mutably: a byte replaced in place changes no length.
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, u8> {
        self.0.iter_mut()
    }

    /// Keep the first `len` bytes.
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    /// Remove every byte.
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

impl<'a, const N: usize> IntoIterator for &'a mut Bytes<N> {
    type Item = &'a mut u8;
    type IntoIter = std::slice::IterMut<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<I, const N: usize> Index<I> for Bytes<N>
where
    Vec<u8>: Index<I>,
{
    type Output = <Vec<u8> as Index<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl<I, const N: usize> IndexMut<I> for Bytes<N>
where
    Vec<u8>: IndexMut<I>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<const N: usize> Deref for Bytes<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for Bytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> PartialEq<[u8]> for Bytes<N> {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}

impl<const N: usize, const M: usize> PartialEq<[u8; M]> for Bytes<N> {
    fn eq(&self, other: &[u8; M]) -> bool {
        self.0 == other
    }
}

impl<const N: usize> PartialEq<Vec<u8>> for Bytes<N> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.0 == other
    }
}

impl<const N: usize> From<Bytes<N>> for Vec<u8> {
    fn from(bytes: Bytes<N>) -> Self {
        bytes.0
    }
}

impl<'a, const N: usize> IntoIterator for &'a Bytes<N> {
    type Item = &'a u8;
    type IntoIter = std::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
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
    const NODE: &'static ShapeNode = &ShapeNode::Seq {
        cap: N,
        element: &ShapeNode::U8,
    };
}

/// UTF-8 text of at most `N` bytes.
///
/// The cap counts bytes, not characters: it bounds the wire, and a
/// character count would not. Nothing normalizes the text — two byte
/// strings that look alike are two values.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text<const N: usize>(String);

impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

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

impl<const N: usize> AsRef<str> for Text<N> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> PartialEq<str> for Text<N> {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl<const N: usize> From<Text<N>> for String {
    fn from(text: Text<N>) -> Self {
        text.0
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
    const NODE: &'static ShapeNode = &ShapeNode::Text { cap: N };
}
