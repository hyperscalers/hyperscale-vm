//! The shape derive against the encoding it describes.
//!
//! The bar is that a shape and the bytes agree: a value's encoding is
//! walked against its own shape, and every field the shape names is read
//! at the width it claims. A derive that drifts is caught as a walk that
//! runs out of bytes or ends with some left over, rather than as a
//! consumer's problem later.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{
    Capped, DecodeError, Hbor, HborBound, HborShape, LengthFree, Name, NodeId, ShapeFault,
    ShapeField, ShapeTable, ShapeValue, ShapeVariant, Text, TypeShape, from_slice, to_vec,
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

/// A chain of names, which a reader walks and the encoding spends
/// nothing on.
fn named_chain(links: u32) -> Result<(ShapeTable, NodeId), ShapeFault> {
    let mut table = ShapeTable::new();
    let mut id = table.push(TypeShape::U8)?;
    for link in 0..links {
        id = table.push(TypeShape::Named {
            name: Name::new(format!("n{link}")).expect("a name"),
            shape: id,
        })?;
    }
    Ok((table, id))
}

/// What bounds a walk over a shape is how tall the shape stands, not how
/// deep its values nest: a name and a discriminant are levels of the
/// tree that the encoding spends nothing on, so a table refused only on
/// the second figure would admit a chain no reader could follow.
#[test]
fn a_shape_taller_than_a_reader_walks_is_refused_where_it_joins() {
    let (table, root) = named_chain(180).expect("a chain a reader walks");
    assert_eq!(table.depth(root), 0, "no name is a level on the wire");
    assert_eq!(table.read(root, &[7]), Ok(ShapeValue::U8(7)));

    assert_eq!(named_chain(400).map(|_| ()), Err(ShapeFault::TooTall));
}

/// And the refusal is the decoder's too, where a table arrives from a
/// peer rather than from a type.
#[test]
fn a_table_taller_than_a_reader_walks_is_refused_at_decode() {
    let (table, _) = named_chain(180).expect("a chain a reader walks");
    let bytes = to_vec(&table).expect("a table encodes");
    assert_eq!(from_slice::<ShapeTable>(&bytes), Ok(table));

    // A longer chain than a table would hold, spelled straight onto the
    // wire so nothing measures it before the decoder does.
    let mut nodes = vec![TypeShape::U8];
    for link in 0..400u32 {
        nodes.push(TypeShape::Named {
            name: Name::new(format!("m{link}")).expect("a name"),
            shape: NodeId(u32::try_from(nodes.len() - 1).expect("a short table")),
        });
    }
    let bytes = to_vec(&nodes).expect("the nodes encode");
    assert_eq!(
        from_slice::<ShapeTable>(&bytes),
        Err(DecodeError::FailedValidation(
            "shape stands past the levels a reader of one walks"
        ))
    );
}

/// A shape whose levels each name the one below them twice: the nodes
/// grow one per level and the walk doubles.
fn shared_subtrees(levels: u32) -> Result<(ShapeTable, NodeId), ShapeFault> {
    let mut table = ShapeTable::new();
    let mut id = table.push(TypeShape::Tuple(Vec::new()))?;
    for _ in 0..levels {
        id = table.push(TypeShape::Tuple(vec![id, id]))?;
    }
    Ok((table, id))
}

/// A subtree two nodes share is stored once and walked once for each, so
/// the nodes a table holds bound neither what rendering it costs nor what
/// reading a value against it allocates. Nothing else in the measure
/// catches this: the nodes are few, the tree is shallow, and a run of
/// units is as wide as it is narrow — zero bytes either way.
#[test]
fn a_shape_whose_walk_outgrows_its_table_is_refused() {
    let (table, root) = shared_subtrees(15).expect("a walk a reader performs");
    assert_eq!(table.len(), 16, "one node per level");
    assert_eq!(table.most(root), 0, "and no width to refuse it by");
    assert_eq!(table.depth(root), 15, "well inside what a decoder follows");
    assert!(table.read(root, &[]).is_ok());

    assert!(matches!(
        shared_subtrees(20).map(|_| ()),
        Err(ShapeFault::TooBroad(_))
    ));
}

/// And the refusal is the decoder's, where the table arrives from a peer.
#[test]
fn a_table_whose_walk_outgrows_it_is_refused_at_decode() {
    let mut nodes = vec![TypeShape::Tuple(Vec::new())];
    for _ in 0..20 {
        let below = NodeId(u32::try_from(nodes.len() - 1).expect("a short table"));
        nodes.push(TypeShape::Tuple(vec![below, below]));
    }
    let bytes = to_vec(&nodes).expect("the nodes encode");
    assert!(bytes.len() < 256, "under a quarter kibibyte on the wire");
    assert_eq!(
        from_slice::<ShapeTable>(&bytes),
        Err(DecodeError::FailedValidation(
            "shape walks more positions than a reader of one visits"
        ))
    );
}
