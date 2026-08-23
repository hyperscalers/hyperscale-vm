//! The shape derive against the encoding it describes.
//!
//! The bar is that a shape and the bytes agree: a value's encoding is
//! walked against its own shape, and every field the shape names is read
//! at the width it claims. A derive that drifts is caught as a walk that
//! runs out of bytes or ends with some left over, rather than as a
//! consumer's problem later.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::shape::shape_of;
use hyperscale_hbor::{
    Hbor, HborShape, ShapeField, ShapeTable, ShapeVariant, TypeShape, to_vec, varint,
};

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
struct Inner {
    tag: u8,
    label: String,
}

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
#[hbor(transparent)]
struct Wrapped(u64);

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
struct Unit;

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
struct Positional(Inner, Wrapped);

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
enum Choice {
    Nothing,
    Pair(u32, bool),
    #[hbor(discriminant = 9)]
    Named {
        held: Option<Inner>,
    },
}

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
struct Everything {
    fixed: [u8; 4],
    many: Vec<u16>,
    distinct: BTreeSet<u64>,
    by_key: BTreeMap<String, Choice>,
    picked: Choice,
    wrapped: Wrapped,
    #[hbor(skip)]
    local: u8,
}

/// A named type is an entry under its kebab name, referenced by it.
#[test]
fn a_declared_type_is_registered_and_referenced() {
    let (shape, types) = shape_of::<Everything>();
    assert_eq!(shape, TypeShape::Ref("everything".into()));
    let mut names: Vec<&str> = types.keys().map(String::as_str).collect();
    names.sort_unstable();
    // `Wrapped` is transparent, so it is a name and not an entry.
    assert_eq!(names, ["choice", "everything", "inner"]);
}

/// A tuple struct and a unit are the same form at different widths, and
/// neither carries a field name because neither has one.
#[test]
fn positional_and_unit_declare_tuples() {
    let (_, types) = shape_of::<Positional>();
    assert_eq!(
        types["positional"],
        TypeShape::Tuple(vec![TypeShape::Ref("inner".into()), TypeShape::U64])
    );
    let (_, types) = shape_of::<Unit>();
    assert_eq!(types["unit"], TypeShape::Tuple(Vec::new()));
}

/// A variant carries the byte the wire carries, pinned or positional, and
/// its content is the form its fields take.
#[test]
fn variants_carry_their_names_and_their_discriminants() {
    let (_, types) = shape_of::<Choice>();
    assert_eq!(
        types["choice"],
        TypeShape::Enum(vec![
            ShapeVariant {
                name: "nothing".into(),
                discriminant: 0,
                content: TypeShape::Tuple(Vec::new()),
            },
            ShapeVariant {
                name: "pair".into(),
                discriminant: 1,
                content: TypeShape::Tuple(vec![TypeShape::U32, TypeShape::Bool]),
            },
            ShapeVariant {
                name: "named".into(),
                discriminant: 9,
                content: TypeShape::Struct(vec![ShapeField {
                    name: "held".into(),
                    shape: TypeShape::Option(Box::new(TypeShape::Ref("inner".into()))),
                }]),
            },
        ])
    );
}

/// A skipped field is on neither the wire nor the shape, and a
/// transparent wrapper is a name on neither.
#[test]
fn the_shape_holds_what_the_wire_holds() {
    let (_, types) = shape_of::<Everything>();
    let TypeShape::Struct(fields) = &types["everything"] else {
        panic!("a struct describes as a struct");
    };
    let named: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert_eq!(
        named,
        ["fixed", "many", "distinct", "by_key", "picked", "wrapped"]
    );
    assert_eq!(fields[5].shape, TypeShape::U64);
}

/// The whole point, end to end: a consumer holding the shape and the
/// bytes reads the value and nothing is left over.
#[test]
fn a_value_walks_its_own_shape() {
    let value = Everything {
        fixed: [1, 2, 3, 4],
        many: vec![7, 8],
        distinct: [4, 9].into_iter().collect(),
        by_key: [
            ("a".to_owned(), Choice::Nothing),
            (
                "b".to_owned(),
                Choice::Named {
                    held: Some(Inner {
                        tag: 3,
                        label: "in".to_owned(),
                    }),
                },
            ),
        ]
        .into_iter()
        .collect(),
        picked: Choice::Pair(11, true),
        wrapped: Wrapped(12),
        local: 200,
    };
    let bytes = to_vec(&value).expect("encodes");
    let (shape, types) = shape_of::<Everything>();
    let mut walk = Walk {
        bytes: &bytes,
        types: &types,
    };
    walk.value(&shape);
    assert!(walk.bytes.is_empty(), "the shape accounts for every byte");
}

/// Reads a payload against a shape, taking exactly what the shape claims.
struct Walk<'b> {
    bytes: &'b [u8],
    types: &'b ShapeTable,
}

impl Walk<'_> {
    const fn take(&mut self, count: usize) -> &[u8] {
        let (taken, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        taken
    }

    fn len(&mut self) -> usize {
        let (len, read) = varint::read(self.bytes).expect("a length");
        self.bytes = &self.bytes[read..];
        len
    }

    fn value(&mut self, shape: &TypeShape) {
        match shape {
            TypeShape::Bool | TypeShape::U8 | TypeShape::I8 => drop(self.take(1)),
            TypeShape::U16 | TypeShape::I16 => drop(self.take(2)),
            TypeShape::U32 | TypeShape::I32 => drop(self.take(4)),
            TypeShape::U64 | TypeShape::I64 => drop(self.take(8)),
            TypeShape::U128 | TypeShape::I128 => drop(self.take(16)),
            TypeShape::ByteArray(width) => drop(self.take(*width as usize)),
            TypeShape::Text => {
                let len = self.len();
                let text = self.take(len);
                core::str::from_utf8(text).expect("utf-8");
            }
            TypeShape::Seq(element) | TypeShape::Set(element) => {
                for _ in 0..self.len() {
                    self.value(element);
                }
            }
            TypeShape::Map { key, value } => {
                for _ in 0..self.len() {
                    self.value(key);
                    self.value(value);
                }
            }
            TypeShape::Option(held) => {
                if self.take(1)[0] == 1 {
                    self.value(held);
                }
            }
            TypeShape::Tuple(elements) => {
                for element in elements {
                    self.value(element);
                }
            }
            TypeShape::Struct(fields) => {
                for field in fields {
                    self.value(&field.shape);
                }
            }
            TypeShape::Enum(variants) => {
                let discriminant = self.take(1)[0];
                let variant = variants
                    .iter()
                    .find(|variant| variant.discriminant == discriminant)
                    .expect("a declared variant");
                self.value(&variant.content);
            }
            TypeShape::Ref(name) => {
                let named = self.types.get(name).expect("a declared type").clone();
                self.value(&named);
            }
        }
    }
}
