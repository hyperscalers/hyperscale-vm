//! Describing a type to a consumer that does not have it.
//!
//! The encoding is schema-external: bytes carry content and nothing else,
//! so a decoder without the type decodes nothing. A [`TypeShape`] is that
//! type written down — enough to walk a payload and name what was read,
//! and no more. It says how to decode, never how to render.
//!
//! Shapes compose the way the codec composes. [`HborShape`] is derived
//! beside [`HborEncode`](crate::HborEncode) and builds a struct's shape
//! from its fields' own impls, so the two cannot describe different
//! bytes. Nothing on the codec path reads one.
//!
//! # Nominal and anonymous
//!
//! A named type — a struct, an enum — registers its definition in a
//! [`ShapeRegistry`] under its kebab name and is referenced as
//! [`TypeShape::Ref`]. Everything else — `Option<T>`, a sequence, a
//! tuple — is written inline where it is used. So a shape is a closed
//! tree over one table, a type reached from two places is stored once,
//! and a type that reaches itself terminates at its own name.
//!
//! A `transparent` wrapper is a name and not a layer on the wire, and
//! the shape follows the wire: it registers nothing and shapes as its
//! inner type. A type whose *name* is what a consumer needs states its
//! impl by hand.

use std::collections::{BTreeMap, BTreeSet};

use crate::{DEFAULT_MAX_DEPTH, DecodeError, Decoder, Hbor};

/// Every type a consumer's shapes may reference, by name.
pub type ShapeTable = BTreeMap<String, TypeShape>;

/// The levels a shape may nest, resolved.
///
/// Generous against what a monomorphic record reaches and finite against
/// what a hand-written one could claim. One number rather than a cap per
/// consumer: the walk that resolves a reference is the walk that counts
/// levels, so a reference cycle is refused by the same bound that
/// refuses a type nested too far.
pub const MAX_SHAPE_DEPTH: usize = 16;

/// A type, as a consumer without it must read one.
///
/// The vocabulary is what the encoding admits and nothing beside it:
/// there is no form here that no value can be written in.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[hbor(crate = crate)]
pub enum TypeShape {
    /// One byte, `0` or `1`.
    Bool,
    /// An unsigned 8-bit integer. Every integer is little-endian at its
    /// own width and carries no length.
    U8,
    /// An unsigned 16-bit integer.
    U16,
    /// An unsigned 32-bit integer.
    U32,
    /// An unsigned 64-bit integer.
    U64,
    /// An unsigned 128-bit integer.
    U128,
    /// A signed 8-bit integer.
    I8,
    /// A signed 16-bit integer.
    I16,
    /// A signed 32-bit integer.
    I32,
    /// A signed 64-bit integer.
    I64,
    /// A signed 128-bit integer.
    I128,
    /// A length then that many bytes of UTF-8.
    ///
    /// Separate from a byte sequence because the validity is a decoding
    /// fact: bytes that are not UTF-8 are not a value of this shape.
    Text,
    /// Exactly this many bytes, with no length field of its own.
    ByteArray(u32),
    /// A length then that many elements.
    Seq(Box<Self>),
    /// A length then that many elements, strictly ascending.
    Set(Box<Self>),
    /// A length then that many key-value pairs, keys strictly ascending.
    Map {
        /// The key's shape.
        key: Box<Self>,
        /// The value's shape.
        value: Box<Self>,
    },
    /// `0`, or `1` followed by the payload.
    Option(Box<Self>),
    /// Its elements in order, with nothing between them. Also what a
    /// tuple struct, a tuple variant, and a unit are.
    Tuple(Vec<Self>),
    /// Its fields in declaration order. The names are the whole reason a
    /// decoded position becomes a fact.
    Struct(Vec<ShapeField>),
    /// A one-byte discriminant then that variant's content.
    Enum(Vec<ShapeVariant>),
    /// A named type's definition, held once in the [`ShapeTable`].
    Ref(String),
}

/// One named field of a struct.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[hbor(crate = crate)]
pub struct ShapeField {
    /// The field's name, as its author spelled it.
    pub name: String,
    /// What the field holds.
    pub shape: TypeShape,
}

/// One variant of an enum.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[hbor(crate = crate)]
pub struct ShapeVariant {
    /// The variant's name, as its author spelled it.
    pub name: String,
    /// The byte the wire carries. Stated rather than positional, because
    /// a variant may pin its own and the position would then be a second
    /// answer.
    pub discriminant: u8,
    /// What follows the discriminant: a [`TypeShape::Struct`] for named
    /// fields, a [`TypeShape::Tuple`] otherwise — empty for a unit.
    pub content: TypeShape,
}

/// Why a shape cannot be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShapeFault {
    /// A reference to a type the table does not hold.
    #[error("shape references type {0:?}, which is not declared")]
    Unresolved(String),
    /// The walk ran out of budget: a shape nested past the cap, or a
    /// reference cycle, which are the same exhaustion seen twice.
    #[error("shape nests past its cap, or references itself")]
    TooDeep,
    /// A sequence, set, or map over an element that occupies no bytes.
    ///
    /// A length is then a count no input pays for, so a claimed one
    /// cannot be bounded by the bytes that remain. The codec refuses the
    /// same thing at compile time, where a `Vec<()>` is unwritable.
    #[error("a run over an element that carries no bytes is a count nothing pays for")]
    ZeroWidth,
}

impl TypeShape {
    /// The decoder levels a value of this shape spends, proving on the
    /// way that a consumer can walk it at all.
    ///
    /// Three properties, one walk: every reference resolves inside
    /// `types`, no run is over an element carrying no bytes, and the
    /// whole is finite. `budget` bounds the walk rather than the answer
    /// — every descent spends one, including a reference hop that costs
    /// the decoder nothing — so a cycle exhausts the same bound a type
    /// nested too far does, and there is no second check to disagree
    /// with this one.
    ///
    /// # Errors
    ///
    /// [`ShapeFault`] for a reference the table does not hold, a run
    /// nothing pays for, or a walk past `budget`.
    pub fn readable(&self, types: &ShapeTable, budget: usize) -> Result<usize, ShapeFault> {
        self.walk(types, budget).map(|(depth, _)| depth)
    }

    /// The fewest bytes any value of this shape can occupy.
    ///
    /// What bounds a claimed length against the bytes that remain, on
    /// the same terms [`HborWidth::MIN_ENCODED_LEN`](crate::HborWidth)
    /// states for a type.
    ///
    /// # Errors
    ///
    /// [`ShapeFault`], as [`readable`](Self::readable).
    pub fn min_encoded_len(&self, types: &ShapeTable, budget: usize) -> Result<usize, ShapeFault> {
        self.walk(types, budget).map(|(_, least)| least)
    }

    /// The levels this shape spends and the fewest bytes it occupies,
    /// read off one another in one pass.
    fn walk(&self, types: &ShapeTable, budget: usize) -> Result<(usize, usize), ShapeFault> {
        let Some(remaining) = budget.checked_sub(1) else {
            return Err(ShapeFault::TooDeep);
        };
        // A composite spends one level on its children whether or not it
        // has any: the encoder charges the level before it knows.
        let under = |shapes: &mut dyn Iterator<Item = &Self>| {
            let mut deepest = None::<usize>;
            let mut least = 0usize;
            for shape in shapes {
                let (depth, width) = shape.walk(types, remaining)?;
                deepest = Some(deepest.map_or(depth, |seen: usize| seen.max(depth)));
                least += width;
            }
            Ok((deepest.map_or(0, |depth| depth + 1), least))
        };
        // A run is a length then its elements: one byte at its shortest,
        // and unbounded unless one element costs something.
        let run = |element: &Self| {
            let (depth, width) = element.walk(types, remaining)?;
            if width == 0 {
                return Err(ShapeFault::ZeroWidth);
            }
            Ok((depth + 1, 1))
        };
        match self {
            // A length with nothing under it, and the one-byte scalars.
            Self::Bool | Self::U8 | Self::I8 | Self::Text => Ok((0, 1)),
            Self::U16 | Self::I16 => Ok((0, 2)),
            Self::U32 | Self::I32 => Ok((0, 4)),
            Self::U64 | Self::I64 => Ok((0, 8)),
            Self::U128 | Self::I128 => Ok((0, 16)),
            Self::ByteArray(width) => Ok((0, *width as usize)),
            Self::Seq(element) | Self::Set(element) => run(element),
            Self::Map { key, value } => {
                let (key_depth, key_width) = key.walk(types, remaining)?;
                let (value_depth, value_width) = value.walk(types, remaining)?;
                if key_width + value_width == 0 {
                    return Err(ShapeFault::ZeroWidth);
                }
                Ok((key_depth.max(value_depth) + 1, 1))
            }
            // The discriminant byte, with `None` carrying nothing beside
            // it.
            Self::Option(held) => Ok((held.walk(types, remaining)?.0 + 1, 1)),
            Self::Tuple(elements) => under(&mut elements.iter()),
            Self::Struct(fields) => under(&mut fields.iter().map(|field| &field.shape)),
            // The discriminant is a byte the enum writes itself; every
            // level below it belongs to the variant's own content, and
            // the lightest variant is what no encoding is shorter than.
            Self::Enum(variants) => {
                let mut deepest = None::<usize>;
                let mut lightest = None::<usize>;
                for variant in variants {
                    let (depth, width) = variant.content.walk(types, remaining)?;
                    deepest = Some(deepest.map_or(depth, |seen: usize| seen.max(depth)));
                    lightest = Some(lightest.map_or(width, |seen: usize| seen.min(width)));
                }
                Ok((deepest.unwrap_or(0), 1 + lightest.unwrap_or(0)))
            }
            Self::Ref(name) => types
                .get(name)
                .ok_or_else(|| ShapeFault::Unresolved(name.clone()))?
                .walk(types, remaining),
        }
    }
}

/// A value read against a shape: what a consumer holding the bytes and
/// the [`TypeShape`] gets back.
///
/// One variant per form the vocabulary admits, so a reader walks the
/// value the way it would have walked the shape. Field and variant names
/// ride along, because the name is what turns a decoded position into a
/// fact and re-reading the shape to recover it is a second walk over the
/// same ground.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShapeValue {
    /// A boolean.
    Bool(bool),
    /// An unsigned 8-bit integer.
    U8(u8),
    /// An unsigned 16-bit integer.
    U16(u16),
    /// An unsigned 32-bit integer.
    U32(u32),
    /// An unsigned 64-bit integer.
    U64(u64),
    /// An unsigned 128-bit integer.
    U128(u128),
    /// A signed 8-bit integer.
    I8(i8),
    /// A signed 16-bit integer.
    I16(i16),
    /// A signed 32-bit integer.
    I32(i32),
    /// A signed 64-bit integer.
    I64(i64),
    /// A signed 128-bit integer.
    I128(i128),
    /// Text.
    Text(String),
    /// A fixed-width run of bytes.
    ByteArray(Vec<u8>),
    /// A sequence's elements, in order.
    Seq(Vec<Self>),
    /// A set's elements, in the order they were written.
    Set(Vec<Self>),
    /// A map's pairs, in the order they were written.
    Map(Vec<(Self, Self)>),
    /// An optional payload.
    Option(Option<Box<Self>>),
    /// A tuple's elements. Also what a tuple struct and a unit read as.
    Tuple(Vec<Self>),
    /// A struct's fields, named and in declaration order.
    Struct(Vec<(String, Self)>),
    /// The variant the discriminant selected, and what followed it.
    Variant {
        /// The variant's name.
        name: String,
        /// The byte the wire carried.
        discriminant: u8,
        /// What followed it: a struct or a tuple.
        content: Box<Self>,
    },
}

/// Why a payload could not be read against a shape.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// The shape itself cannot be walked, whatever the bytes are.
    #[error(transparent)]
    Unreadable(#[from] ShapeFault),
    /// The bytes are malformed, truncated, non-canonical, or longer than
    /// the shape accounts for.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
}

impl TypeShape {
    /// Read one complete value of this shape from `bytes`.
    ///
    /// What a consumer holding a package's metadata and a payload does
    /// with the two. The bytes must be exactly one value: anything left
    /// over is a payload the shape does not describe.
    ///
    /// Checked is everything the shape can know — every width, every
    /// length minimal and payable by the bytes that remain, text valid
    /// UTF-8, every discriminant declared, and no byte unaccounted for.
    /// Not checked is the ascent of a set's or a map's keys: that order
    /// is the element type's own, and a shape carries structure rather
    /// than a comparison. A reader rejecting on a guess at it would
    /// refuse payloads the chain accepted.
    ///
    /// Nesting is bounded by [`readable`](Self::readable), which runs
    /// first: a shape within the cap bounds this walk's own recursion,
    /// because a value nests exactly as deep as the shape describing it
    /// however many elements it holds.
    ///
    /// # Errors
    ///
    /// [`ReadError`] for a shape that cannot be walked, or bytes it does
    /// not describe.
    pub fn read(&self, bytes: &[u8], types: &ShapeTable) -> Result<ShapeValue, ReadError> {
        self.readable(types, MAX_SHAPE_DEPTH)?;
        let mut decoder = Decoder::new(bytes, DEFAULT_MAX_DEPTH);
        let value = self.read_from(&mut decoder, types)?;
        decoder.finish()?;
        Ok(value)
    }

    /// Read one value, leaving whatever follows it for the caller.
    ///
    /// Total over a shape [`readable`](Self::readable) has passed, and
    /// safe over one it has not: an unresolved reference is an error
    /// here rather than a panic, because a reader is handed metadata it
    /// did not write.
    fn read_from(
        &self,
        decoder: &mut Decoder<'_>,
        types: &ShapeTable,
    ) -> Result<ShapeValue, ReadError> {
        // Every width the encoding fixes, read as the little-endian run
        // it is.
        macro_rules! fixed {
            ($ty:ty, $variant:ident) => {{
                let bytes = decoder.read_array::<{ ::core::mem::size_of::<$ty>() }>()?;
                Ok(ShapeValue::$variant(<$ty>::from_le_bytes(bytes)))
            }};
        }
        match self {
            Self::Bool => match decoder.read_u8()? {
                0 => Ok(ShapeValue::Bool(false)),
                1 => Ok(ShapeValue::Bool(true)),
                other => Err(DecodeError::InvalidBool(other).into()),
            },
            Self::U8 => fixed!(u8, U8),
            Self::U16 => fixed!(u16, U16),
            Self::U32 => fixed!(u32, U32),
            Self::U64 => fixed!(u64, U64),
            Self::U128 => fixed!(u128, U128),
            Self::I8 => fixed!(i8, I8),
            Self::I16 => fixed!(i16, I16),
            Self::I32 => fixed!(i32, I32),
            Self::I64 => fixed!(i64, I64),
            Self::I128 => fixed!(i128, I128),
            Self::Text => {
                let len = decoder.read_len(1)?;
                let bytes = decoder.read_slice(len)?;
                core::str::from_utf8(bytes)
                    .map(|text| ShapeValue::Text(text.to_owned()))
                    .map_err(|_| DecodeError::InvalidUtf8.into())
            }
            Self::ByteArray(width) => Ok(ShapeValue::ByteArray(
                decoder.read_slice(*width as usize)?.to_vec(),
            )),
            Self::Seq(element) | Self::Set(element) => {
                let len = Self::run_length(decoder, types, element)?;
                let mut read = Vec::with_capacity(decoder.reserve_hint::<ShapeValue>(len));
                for _ in 0..len {
                    read.push(element.read_from(decoder, types)?);
                }
                Ok(if matches!(self, Self::Seq(_)) {
                    ShapeValue::Seq(read)
                } else {
                    ShapeValue::Set(read)
                })
            }
            Self::Map { key, value } => {
                let pair = key.min_encoded_len(types, MAX_SHAPE_DEPTH)?
                    + value.min_encoded_len(types, MAX_SHAPE_DEPTH)?;
                if pair == 0 {
                    return Err(ShapeFault::ZeroWidth.into());
                }
                let len = decoder.read_len(pair)?;
                let mut pairs = Vec::with_capacity(decoder.reserve_hint::<ShapeValue>(len));
                for _ in 0..len {
                    let read = key.read_from(decoder, types)?;
                    pairs.push((read, value.read_from(decoder, types)?));
                }
                Ok(ShapeValue::Map(pairs))
            }
            Self::Option(held) => match decoder.read_u8()? {
                0 => Ok(ShapeValue::Option(None)),
                1 => held
                    .read_from(decoder, types)
                    .map(|read| ShapeValue::Option(Some(Box::new(read)))),
                other => Err(DecodeError::InvalidDiscriminant(other).into()),
            },
            Self::Tuple(elements) => {
                let mut read = Vec::with_capacity(elements.len());
                for element in elements {
                    read.push(element.read_from(decoder, types)?);
                }
                Ok(ShapeValue::Tuple(read))
            }
            Self::Struct(fields) => {
                let mut read = Vec::with_capacity(fields.len());
                for field in fields {
                    let value = field.shape.read_from(decoder, types)?;
                    read.push((field.name.clone(), value));
                }
                Ok(ShapeValue::Struct(read))
            }
            Self::Enum(variants) => {
                let discriminant = decoder.read_u8()?;
                let variant = variants
                    .iter()
                    .find(|variant| variant.discriminant == discriminant)
                    .ok_or(DecodeError::InvalidDiscriminant(discriminant))?;
                Ok(ShapeValue::Variant {
                    name: variant.name.clone(),
                    discriminant,
                    content: Box::new(variant.content.read_from(decoder, types)?),
                })
            }
            Self::Ref(name) => types
                .get(name)
                .ok_or_else(|| ShapeFault::Unresolved(name.clone()))?
                .read_from(decoder, types),
        }
    }

    /// How many elements a run claims, bounded by what the bytes could
    /// pay for.
    ///
    /// The element's own minimum is what makes that bound real: a
    /// claimed length is refused before anything is allocated for it.
    fn run_length(
        decoder: &mut Decoder<'_>,
        types: &ShapeTable,
        element: &Self,
    ) -> Result<usize, ReadError> {
        let least = element.min_encoded_len(types, MAX_SHAPE_DEPTH)?;
        if least == 0 {
            return Err(ShapeFault::ZeroWidth.into());
        }
        Ok(decoder.read_len(least)?)
    }
}

/// A type that can describe itself to a consumer that does not have it.
///
/// Derived rather than written, so a shape and an encoding are one
/// derivation from one declaration. Nothing should ever author one by
/// hand except where the name is the point — the address family — and
/// there the hand impl is what carries the name the wire drops.
pub trait HborShape {
    /// Register this type and everything it names in `types`, and return
    /// the shape a value of it has.
    ///
    /// A nominal type registers its definition and returns a
    /// [`TypeShape::Ref`] to it; anything else returns its shape inline
    /// and registers nothing.
    fn shape(types: &mut ShapeRegistry) -> TypeShape;
}

/// The table under construction, and who owns each name in it.
///
/// Names are what a shape references and what a consumer looks a type up
/// by, so two types cannot share one. The Rust path of whoever claimed a
/// name is kept beside it for exactly as long as it takes to say so.
#[derive(Clone, Debug, Default)]
pub struct ShapeRegistry {
    types: ShapeTable,
    owners: BTreeMap<String, &'static str>,
    building: BTreeSet<String>,
}

impl ShapeRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `owner`'s definition under `name`, and reference it.
    ///
    /// The name is reserved before `define` runs, so a type that reaches
    /// itself finds its own name and closes the cycle rather than
    /// recurring forever. A name already held by the same owner is that
    /// same type reached a second way, and its definition is not rebuilt.
    ///
    /// `owner` is the claimant's Rust path, which the derive supplies as
    /// [`core::any::type_name`].
    ///
    /// # Panics
    ///
    /// If `name` is already held by a different type. A reference
    /// resolves by name, so two types under one would make it ambiguous
    /// — and shapes are built where a package is built, so this is a
    /// build failure naming the collision rather than anything a chain
    /// can reach.
    pub fn nominal(
        &mut self,
        name: &str,
        owner: &'static str,
        define: impl FnOnce(&mut Self) -> TypeShape,
    ) -> TypeShape {
        if let Some(held) = self.owners.get(name) {
            assert!(
                *held == owner,
                "`{name}` already names `{held}`, so `{owner}` would be unreachable under it"
            );
        } else {
            self.owners.insert(name.to_owned(), owner);
            self.building.insert(name.to_owned());
            let defined = define(self);
            self.building.remove(name);
            self.types.insert(name.to_owned(), defined);
        }
        TypeShape::Ref(name.to_owned())
    }

    /// The types registered so far.
    #[must_use]
    pub const fn types(&self) -> &ShapeTable {
        &self.types
    }

    /// The finished table.
    ///
    /// # Panics
    ///
    /// If a definition is still being built, which only a caller holding
    /// the registry inside its own `define` could arrange.
    #[must_use]
    pub fn into_types(self) -> ShapeTable {
        assert!(self.building.is_empty(), "a definition is still open");
        self.types
    }
}

/// The shape of `T`, and everything `T` names, as a table on its own.
#[must_use]
pub fn shape_of<T: HborShape>() -> (TypeShape, ShapeTable) {
    let mut registry = ShapeRegistry::new();
    let shape = T::shape(&mut registry);
    (shape, registry.into_types())
}

macro_rules! primitive {
    ($($ty:ty => $shape:ident),+ $(,)?) => {
        $(impl HborShape for $ty {
            fn shape(_: &mut ShapeRegistry) -> TypeShape {
                TypeShape::$shape
            }
        })+
    };
}

primitive! {
    bool => Bool,
    u8 => U8, u16 => U16, u32 => U32, u64 => U64, u128 => U128,
    i8 => I8, i16 => I16, i32 => I32, i64 => I64, i128 => I128,
    String => Text,
}

impl HborShape for () {
    fn shape(_: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Tuple(Vec::new())
    }
}

impl<const N: usize> HborShape for [u8; N] {
    fn shape(_: &mut ShapeRegistry) -> TypeShape {
        TypeShape::ByteArray(u32::try_from(N).unwrap_or(u32::MAX))
    }
}

impl<T: HborShape> HborShape for Option<T> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Option(Box::new(T::shape(types)))
    }
}

impl<T: HborShape> HborShape for Vec<T> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Seq(Box::new(T::shape(types)))
    }
}

impl<T: HborShape> HborShape for BTreeSet<T> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Set(Box::new(T::shape(types)))
    }
}

impl<K: HborShape, V: HborShape> HborShape for BTreeMap<K, V> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        TypeShape::Map {
            key: Box::new(K::shape(types)),
            value: Box::new(V::shape(types)),
        }
    }
}

// A box and an arc are names for a place: they encode as their contents
// and charge no level, so they describe as their contents too.
impl<T: HborShape + ?Sized> HborShape for Box<T> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        T::shape(types)
    }
}

impl<T: HborShape + ?Sized> HborShape for std::sync::Arc<T> {
    fn shape(types: &mut ShapeRegistry) -> TypeShape {
        T::shape(types)
    }
}

macro_rules! tuple {
    ($($name:ident),+) => {
        impl<$($name: HborShape),+> HborShape for ($($name,)+) {
            fn shape(types: &mut ShapeRegistry) -> TypeShape {
                TypeShape::Tuple(::std::vec![$($name::shape(types)),+])
            }
        }
    };
}

tuple!(A, B);
tuple!(A, B, C);
tuple!(A, B, C, D);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{assert_canonical_at_depth, from_slice_with_depth, to_vec_with_depth};

    /// Every form the vocabulary admits, in one table, so a round-trip
    /// covers the whole of it rather than the forms a real type reaches.
    fn every_form() -> ShapeTable {
        let leaf = TypeShape::Enum(vec![
            ShapeVariant {
                name: "nothing".into(),
                discriminant: 0,
                content: TypeShape::Tuple(Vec::new()),
            },
            ShapeVariant {
                name: "pair".into(),
                discriminant: 7,
                content: TypeShape::Tuple(vec![TypeShape::I8, TypeShape::Bool]),
            },
            ShapeVariant {
                name: "named".into(),
                discriminant: 9,
                content: TypeShape::Struct(vec![ShapeField {
                    name: "text".into(),
                    shape: TypeShape::Text,
                }]),
            },
        ]);
        let whole = TypeShape::Struct(vec![
            ShapeField {
                name: "widths".into(),
                shape: TypeShape::Tuple(vec![
                    TypeShape::U8,
                    TypeShape::U16,
                    TypeShape::U32,
                    TypeShape::U64,
                    TypeShape::U128,
                    TypeShape::I16,
                    TypeShape::I32,
                    TypeShape::I64,
                    TypeShape::I128,
                ]),
            },
            ShapeField {
                name: "fixed".into(),
                shape: TypeShape::ByteArray(32),
            },
            ShapeField {
                name: "maybe".into(),
                shape: TypeShape::Option(Box::new(TypeShape::Ref("leaf".into()))),
            },
            ShapeField {
                name: "many".into(),
                shape: TypeShape::Seq(Box::new(TypeShape::U8)),
            },
            ShapeField {
                name: "distinct".into(),
                shape: TypeShape::Set(Box::new(TypeShape::U64)),
            },
            ShapeField {
                name: "by_key".into(),
                shape: TypeShape::Map {
                    key: Box::new(TypeShape::Text),
                    value: Box::new(TypeShape::Ref("leaf".into())),
                },
            },
        ]);
        [("leaf".to_owned(), leaf), ("whole".to_owned(), whole)]
            .into_iter()
            .collect()
    }

    #[test]
    fn every_form_round_trips_canonically() {
        let types = every_form();
        let bytes = to_vec_with_depth(&types, 32).expect("encodes");
        let read: ShapeTable = from_slice_with_depth(&bytes, 32).expect("decodes");
        assert_eq!(read, types);
        assert_canonical_at_depth(&types, 32);
    }

    #[test]
    fn depth_counts_the_levels_a_decoder_spends() {
        let types = every_form();
        // A variant's content is a struct or a tuple, and the level goes
        // to its fields; the discriminant is a byte the enum writes.
        assert_eq!(types["leaf"].readable(&types, 16), Ok(1));
        // The map's own level, the reference its value holds, and that
        // leaf's own — the deepest field is what the record costs.
        assert_eq!(types["whole"].readable(&types, 16), Ok(3));
    }

    #[test]
    fn an_empty_composite_still_spends_its_level() {
        let types = ShapeTable::new();
        assert_eq!(TypeShape::Tuple(Vec::new()).readable(&types, 8), Ok(0));
        assert_eq!(
            TypeShape::Seq(Box::new(TypeShape::U8)).readable(&types, 8),
            Ok(1)
        );
    }

    #[test]
    fn a_reference_to_nothing_is_a_fault() {
        assert_eq!(
            TypeShape::Ref("absent".into()).readable(&ShapeTable::new(), 8),
            Err(ShapeFault::Unresolved("absent".into()))
        );
    }

    #[test]
    fn a_cycle_and_a_deep_nest_exhaust_one_bound() {
        let named = |name: &str, holds: &str| {
            (
                name.to_owned(),
                TypeShape::Struct(vec![ShapeField {
                    name: holds.to_owned(),
                    shape: TypeShape::Option(Box::new(TypeShape::Ref(holds.to_owned()))),
                }]),
            )
        };
        let cyclic: ShapeTable = [named("a", "b"), named("b", "a")].into_iter().collect();
        assert_eq!(cyclic["a"].readable(&cyclic, 16), Err(ShapeFault::TooDeep));

        let deep = (0..8).fold(TypeShape::U8, |inner, _| TypeShape::Seq(Box::new(inner)));
        let empty = ShapeTable::new();
        assert_eq!(deep.readable(&empty, 4), Err(ShapeFault::TooDeep));
        assert_eq!(deep.readable(&empty, 16), Ok(8));
    }

    #[test]
    fn a_name_is_defined_once_and_a_cycle_closes_on_it() {
        let mut types = ShapeRegistry::new();
        let outer = types.nominal("node", "Node", |types| {
            TypeShape::Struct(vec![ShapeField {
                name: "next".into(),
                // Reaching the same name mid-definition finds the
                // reservation and returns a reference to it.
                shape: TypeShape::Option(Box::new(types.nominal("node", "Node", |_| {
                    unreachable!("the name is reserved before its body is built")
                }))),
            }])
        });
        assert_eq!(outer, TypeShape::Ref("node".into()));
        assert_eq!(types.into_types().len(), 1);
    }

    #[test]
    #[should_panic(expected = "already names")]
    fn two_types_under_one_name_is_a_build_failure() {
        let mut types = ShapeRegistry::new();
        types.nominal("thing", "one::Thing", |_| TypeShape::U8);
        types.nominal("thing", "two::Thing", |_| TypeShape::Text);
    }
}
