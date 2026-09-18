//! The shape derive against the encoding it describes.
//!
//! The bar is that a shape and the bytes agree: a value's encoding is
//! walked against its own shape, and every field the shape names is read
//! at the width it claims. A derive that drifts is caught as a walk that
//! runs out of bytes or ends with some left over, rather than as a
//! consumer's problem later.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{
    Capped, DecodeError, Hbor, HborBound, HborShape, LengthFree, Name, ShapeField, ShapeTable,
    ShapeValue, ShapeVariant, Text, TypeShape, to_vec,
};

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
#[hbor(length_free)]
struct Closed {
    a: u32,
    b: [u8; 3],
    c: Option<u64>,
    d: (bool, u16),
}

/// The width a type states is the width its published shape measures,
/// with or without a run in it: every shape has a widest value.
#[test]
fn a_shape_measures_the_width_the_type_states() {
    fn agree<T: HborShape>() {
        let (table, root) = ShapeTable::of::<T>();
        assert_eq!(table.most(root), <T as HborBound>::MAX_ENCODED_LEN);
        assert_eq!(table.depth(root), <T as HborBound>::MAX_DEPTH);
    }
    fn length_free<T: LengthFree>() {}
    agree::<Closed>();
    agree::<Unit>();
    agree::<Everything>();
    agree::<Positional>();
    let (table, root) = ShapeTable::of::<Unit>();
    assert_eq!(table.most(root), 0);
    length_free::<Closed>();
}

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
struct Inner {
    tag: u8,
    label: Text<16>,
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
    many: Capped<Vec<u16>, 4>,
    distinct: Capped<BTreeSet<u64>, 4>,
    by_key: Capped<BTreeMap<Text<8>, Choice>, 4>,
    picked: Choice,
    wrapped: Wrapped,
    #[hbor(skip)]
    local: u8,
}

/// A named type is a node under its kebab name, and what it names is
/// found by the name.
#[test]
fn a_declared_type_is_named_and_found_by_its_name() {
    let (table, root) = ShapeTable::of::<Everything>();
    assert_eq!(table.named("Everything"), Some(root));
    let mut names: Vec<&str> = table.names().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    // `Wrapped` is transparent, so it is a name and not a node.
    assert_eq!(names, ["Choice", "Everything", "Inner"]);
}

/// A tuple struct and a unit are the same form at different widths, and
/// neither carries a field name because neither has one.
#[test]
fn positional_and_unit_declare_tuples() {
    let (mut table, root) = ShapeTable::of::<Positional>();
    let Some(TypeShape::Named { shape, .. }) = table.get(root) else {
        panic!("a struct is named");
    };
    let shape = *shape;
    let inner = table.named("Inner").unwrap();
    let word = table.push(TypeShape::U64).unwrap();
    assert_eq!(table.get(shape), Some(&TypeShape::Tuple(vec![inner, word])));
    let (table, root) = ShapeTable::of::<Unit>();
    let Some(TypeShape::Named { shape, .. }) = table.get(root) else {
        panic!("a struct is named");
    };
    assert_eq!(table.get(*shape), Some(&TypeShape::Tuple(Vec::new())));
}

/// A variant carries the byte the wire carries, pinned or positional, and
/// its content is the form its fields take.
#[test]
fn variants_carry_their_names_and_their_discriminants() {
    let (mut table, root) = ShapeTable::of::<Choice>();
    let Some(TypeShape::Named { shape, .. }) = table.get(root) else {
        panic!("an enum is named");
    };
    let shape = *shape;
    let unit = table.push(TypeShape::Tuple(Vec::new())).unwrap();
    let word = table.push(TypeShape::U32).unwrap();
    let boolean = table.push(TypeShape::Bool).unwrap();
    let pair = table.push(TypeShape::Tuple(vec![word, boolean])).unwrap();
    let inner = table.named("Inner").unwrap();
    let maybe = table.push(TypeShape::Option(inner)).unwrap();
    let named = table
        .push(TypeShape::Struct(vec![ShapeField {
            name: Name::declared("held"),
            shape: maybe,
        }]))
        .unwrap();
    assert_eq!(
        table.get(shape),
        Some(&TypeShape::Enum(vec![
            ShapeVariant {
                name: Name::declared("Nothing"),
                discriminant: 0,
                content: unit,
            },
            ShapeVariant {
                name: Name::declared("Pair"),
                discriminant: 1,
                content: pair,
            },
            ShapeVariant {
                name: Name::declared("Named"),
                discriminant: 9,
                content: named,
            },
        ]))
    );
}

/// A skipped field is on neither the wire nor the shape, and a
/// transparent wrapper is a name on neither.
#[test]
fn the_shape_holds_what_the_wire_holds() {
    let (table, root) = ShapeTable::of::<Everything>();
    let Some(TypeShape::Named { shape, .. }) = table.get(root) else {
        panic!("a struct is named");
    };
    let Some(TypeShape::Struct(fields)) = table.get(*shape) else {
        panic!("a struct describes as a struct");
    };
    let named: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert_eq!(
        named,
        ["fixed", "many", "distinct", "by_key", "picked", "wrapped"]
    );
    assert_eq!(table.get(fields[5].shape), Some(&TypeShape::U64));
}

/// The whole point, end to end: a consumer holding the shape and the
/// bytes reads the value, and every field comes back named.
#[test]
fn a_value_reads_back_against_its_own_shape() {
    let value = Everything {
        fixed: [1, 2, 3, 4],
        many: Capped::new(vec![7, 8]).unwrap(),
        distinct: Capped::new([4, 9].into_iter().collect()).unwrap(),
        by_key: Capped::new(
            [
                (Text::try_from("a").unwrap(), Choice::Nothing),
                (
                    Text::try_from("b").unwrap(),
                    Choice::Named {
                        held: Some(Inner {
                            tag: 3,
                            label: Text::try_from("in").unwrap(),
                        }),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap(),
        picked: Choice::Pair(11, true),
        wrapped: Wrapped(12),
        local: 200,
    };
    let bytes = to_vec(&value).expect("encodes");
    let (table, root) = ShapeTable::of::<Everything>();
    let ShapeValue::Struct(fields) = table.read(root, &bytes).expect("reads") else {
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
            name: Name::declared("Pair"),
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
        label: Text::try_from("in").unwrap(),
    };
    let bytes = to_vec(&value).expect("encodes");
    let (table, root) = ShapeTable::of::<Inner>();
    assert!(table.read(root, &bytes).is_ok());

    // A byte too many is a second payload, not a value to ignore.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        table.read(root, &trailing),
        Err(DecodeError::TrailingBytes { .. })
    ));

    // A byte too few runs the reader off the end.
    assert!(table.read(root, &bytes[..bytes.len() - 1]).is_err());

    // A discriminant no variant declares is refused where the typed
    // decoder refuses one.
    let (table, root) = ShapeTable::of::<Choice>();
    assert!(matches!(
        table.read(root, &[200]),
        Err(DecodeError::InvalidDiscriminant(200))
    ));
}

/// A capped run's derived width is the bytes its widest value encodes
/// to, and a claim past the cap is refused where the typed decoder
/// refuses one.
#[test]
fn a_capped_run_is_priced_and_bounded_at_its_cap() {
    let widest = Capped::<Vec<u16>, 4>::new(vec![1, 2, 3, 4]).unwrap();
    let (table, root) = ShapeTable::of::<Capped<Vec<u16>, 4>>();
    let bytes = to_vec(&widest).unwrap();
    assert_eq!(bytes.len(), table.most(root));
    assert_eq!(
        bytes.len(),
        <Capped<Vec<u16>, 4> as HborBound>::MAX_ENCODED_LEN
    );
    assert!(table.read(root, &bytes).is_ok());
    let five = to_vec(&vec![1u16; 5]).unwrap();
    assert_eq!(
        table.read(root, &five),
        Err(DecodeError::BoundExceeded { max: 4, actual: 5 })
    );
}
