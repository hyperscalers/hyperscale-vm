//! The shape derive against the encoding it describes.
//!
//! The bar is that a shape and the bytes agree: a value's encoding is
//! walked against its own shape, and every field the shape names is read
//! at the width it claims. A derive that drifts is caught as a walk that
//! runs out of bytes or ends with some left over, rather than as a
//! consumer's problem later.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{
    DecodeError, Hbor, HborShape, ReadError, ShapeFault, ShapeField, ShapeTable, ShapeValue,
    ShapeVariant, TypeShape, shape_of, to_vec,
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
/// bytes reads the value, and every field comes back named.
#[test]
fn a_value_reads_back_against_its_own_shape() {
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
    let ShapeValue::Struct(fields) = shape.read(&bytes, &types).expect("reads") else {
        panic!("a struct reads as a struct");
    };
    let named: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        named,
        ["fixed", "many", "distinct", "by_key", "picked", "wrapped"]
    );
    assert_eq!(fields[0].1, ShapeValue::ByteArray(vec![1, 2, 3, 4]));
    assert_eq!(
        fields[1].1,
        ShapeValue::Seq(vec![ShapeValue::U16(7), ShapeValue::U16(8)])
    );
    // A skipped field is on neither the wire nor the shape, so the
    // reader accounts for every byte without it.
    assert_eq!(fields[5].1, ShapeValue::U64(12));
    assert_eq!(
        fields[4].1,
        ShapeValue::Variant {
            name: "pair".to_owned(),
            discriminant: 1,
            content: Box::new(ShapeValue::Tuple(vec![
                ShapeValue::U32(11),
                ShapeValue::Bool(true)
            ])),
        }
    );
}

/// Bytes the shape does not describe are refused rather than half-read.
#[test]
fn a_payload_the_shape_does_not_describe_is_refused() {
    let value = Inner {
        tag: 3,
        label: "in".to_owned(),
    };
    let bytes = to_vec(&value).expect("encodes");
    let (shape, types) = shape_of::<Inner>();
    assert!(shape.read(&bytes, &types).is_ok());

    // A byte too many is a second payload, not a value to ignore.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        shape.read(&trailing, &types),
        Err(ReadError::Malformed(DecodeError::TrailingBytes { .. }))
    ));

    // A byte too few runs the reader off the end.
    assert!(matches!(
        shape.read(&bytes[..bytes.len() - 1], &types),
        Err(ReadError::Malformed(_))
    ));

    // A discriminant no variant declares is refused where the typed
    // decoder refuses one.
    let (choice, types) = shape_of::<Choice>();
    assert!(matches!(
        choice.read(&[200], &types),
        Err(ReadError::Malformed(DecodeError::InvalidDiscriminant(200)))
    ));
}

/// A run over an element that carries no bytes is a claimed length no
/// input pays for, so the reader refuses the shape rather than
/// allocating against it.
///
/// The codec refuses the same thing at compile time, where a `Vec<()>`
/// is unwritable; a shape is data, so the refusal happens when it is
/// read.
#[test]
fn a_run_over_nothing_is_refused_before_it_allocates() {
    let types = ShapeTable::new();
    let nothing = TypeShape::Seq(Box::new(TypeShape::Tuple(Vec::new())));
    assert_eq!(
        nothing.read(&[0xFF, 0xFF, 0xFF, 0x7F], &types),
        Err(ReadError::Unreadable(ShapeFault::ZeroWidth))
    );
    // A zero-width array is the same claim spelled another way.
    let empty_array = TypeShape::Seq(Box::new(TypeShape::ByteArray(0)));
    assert_eq!(
        empty_array.read(&[1], &types),
        Err(ReadError::Unreadable(ShapeFault::ZeroWidth))
    );
    // An element that costs something bounds the claim by the bytes.
    let counted = TypeShape::Seq(Box::new(TypeShape::U64));
    assert!(matches!(
        counted.read(&[9, 0, 0], &types),
        Err(ReadError::Malformed(DecodeError::LengthExceedsInput { .. }))
    ));
}

/// A shape a consumer cannot follow is refused before any byte is read.
#[test]
fn an_unfollowable_shape_is_refused_before_the_bytes() {
    let types = ShapeTable::new();
    assert_eq!(
        TypeShape::Ref("absent".into()).read(&[], &types),
        Err(ReadError::Unreadable(ShapeFault::Unresolved(
            "absent".into()
        )))
    );
}
