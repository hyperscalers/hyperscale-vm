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

use crate::Hbor;

/// Every type a consumer's shapes may reference, by name.
pub type ShapeTable = BTreeMap<String, TypeShape>;

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
}

impl TypeShape {
    /// The decoder levels a value of this shape spends, resolving
    /// references through `types`.
    ///
    /// `budget` bounds the walk rather than the answer: every descent
    /// spends one, including a reference hop that costs the decoder
    /// nothing. So a cycle exhausts the same bound that a type nested
    /// too far does, and there is no second check to disagree with this
    /// one.
    ///
    /// # Errors
    ///
    /// [`ShapeFault`] for a reference the table does not hold, or a walk
    /// past `budget`.
    pub fn resolved_depth(&self, types: &ShapeTable, budget: usize) -> Result<usize, ShapeFault> {
        let Some(remaining) = budget.checked_sub(1) else {
            return Err(ShapeFault::TooDeep);
        };
        let deepest = |shapes: &mut dyn Iterator<Item = &Self>| {
            let mut deepest = None::<usize>;
            for shape in shapes {
                let depth = shape.resolved_depth(types, remaining)?;
                deepest = Some(deepest.map_or(depth, |seen| seen.max(depth)));
            }
            Ok(deepest)
        };
        // A composite spends one level on its children whether or not it
        // has any: the encoder charges the level before it knows.
        let under = |shapes: &mut dyn Iterator<Item = &Self>| {
            deepest(shapes).map(|deepest| deepest.map_or(0, |depth| depth + 1))
        };
        match self {
            Self::Bool
            | Self::U8
            | Self::U16
            | Self::U32
            | Self::U64
            | Self::U128
            | Self::I8
            | Self::I16
            | Self::I32
            | Self::I64
            | Self::I128
            | Self::Text
            | Self::ByteArray(_) => Ok(0),
            Self::Seq(element) | Self::Set(element) | Self::Option(element) => {
                Ok(element.resolved_depth(types, remaining)? + 1)
            }
            Self::Map { key, value } => under(&mut [key.as_ref(), value.as_ref()].into_iter()),
            Self::Tuple(elements) => under(&mut elements.iter()),
            Self::Struct(fields) => under(&mut fields.iter().map(|field| &field.shape)),
            // The discriminant is a byte the enum writes itself; every
            // level below it belongs to the variant's own content.
            Self::Enum(variants) => {
                Ok(deepest(&mut variants.iter().map(|variant| &variant.content))?.unwrap_or(0))
            }
            Self::Ref(name) => types
                .get(name)
                .ok_or_else(|| ShapeFault::Unresolved(name.clone()))?
                .resolved_depth(types, remaining),
        }
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
        assert_eq!(types["leaf"].resolved_depth(&types, 16), Ok(1));
        // The map's own level, the reference its value holds, and that
        // leaf's own — the deepest field is what the record costs.
        assert_eq!(types["whole"].resolved_depth(&types, 16), Ok(3));
    }

    #[test]
    fn an_empty_composite_still_spends_its_level() {
        let types = ShapeTable::new();
        assert_eq!(
            TypeShape::Tuple(Vec::new()).resolved_depth(&types, 8),
            Ok(0)
        );
        assert_eq!(
            TypeShape::Seq(Box::new(TypeShape::U8)).resolved_depth(&types, 8),
            Ok(1)
        );
    }

    #[test]
    fn a_reference_to_nothing_is_a_fault() {
        assert_eq!(
            TypeShape::Ref("absent".into()).resolved_depth(&ShapeTable::new(), 8),
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
        assert_eq!(
            cyclic["a"].resolved_depth(&cyclic, 16),
            Err(ShapeFault::TooDeep)
        );

        let deep = (0..8).fold(TypeShape::U8, |inner, _| TypeShape::Seq(Box::new(inner)));
        let empty = ShapeTable::new();
        assert_eq!(deep.resolved_depth(&empty, 4), Err(ShapeFault::TooDeep));
        assert_eq!(deep.resolved_depth(&empty, 16), Ok(8));
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
