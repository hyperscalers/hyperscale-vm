//! The static shape tree and the bounds folded off it.
//!
//! Three things hold the folds honest: the figures are constants, so a
//! type's bound is stated beside its shape; they agree with the encoder,
//! which is what charges the levels and writes the bytes; and where the
//! recursive walk over a [`TypeShape`] answers, they answer the same.

use std::collections::BTreeMap;

use hyperscale_hbor::node::{max_depth, max_encoded_len, min_encoded_len};
use hyperscale_hbor::shape::{MAX_SHAPE_DEPTH, Resolution};
use hyperscale_hbor::{
    EncodeError, Hbor, HborBound, ShapeField, ShapeNode, ShapeTable, ShapeVariant, TypeShape,
    to_vec, to_vec_with_depth,
};

#[derive(Debug, PartialEq, Eq, Hbor)]
struct Record {
    a: u32,
    b: [u8; 3],
    c: Option<u64>,
    d: (bool, u16),
}

const RECORD: &ShapeNode = &ShapeNode::Named {
    name: "record",
    shape: &ShapeNode::Struct(&[
        ("a", &ShapeNode::U32),
        ("b", &ShapeNode::ByteArray(3)),
        ("c", &ShapeNode::Option(&ShapeNode::U64)),
        ("d", &ShapeNode::Tuple(&[&ShapeNode::Bool, &ShapeNode::U16])),
    ]),
};

/// The widest variant sits in the middle, so a fold that took the last
/// variant, or the first, would be wrong.
#[derive(Debug, PartialEq, Eq, Hbor)]
enum Choice {
    Nothing,
    Wide { held: u128, more: u64 },
    Narrow(u8),
}

const CHOICE: &ShapeNode = &ShapeNode::Named {
    name: "choice",
    shape: &ShapeNode::Enum(&[
        ("nothing", 0, &ShapeNode::Tuple(&[])),
        (
            "wide",
            1,
            &ShapeNode::Struct(&[("held", &ShapeNode::U128), ("more", &ShapeNode::U64)]),
        ),
        ("narrow", 2, &ShapeNode::Tuple(&[&ShapeNode::U8])),
    ]),
};

const THREE_WORDS: &ShapeNode = &ShapeNode::Seq {
    cap: 3,
    element: &ShapeNode::U64,
};

const PAIRS: &ShapeNode = &ShapeNode::Map {
    cap: 2,
    key: &ShapeNode::U8,
    value: &ShapeNode::Option(&ShapeNode::U16),
};

const LABEL: &ShapeNode = &ShapeNode::Text { cap: 300 };

/// Every figure is a constant, read off the tree at compile time.
const _: () = {
    assert!(max_encoded_len(RECORD) == 4 + 3 + 9 + 3);
    assert!(min_encoded_len(RECORD) == 4 + 3 + 1 + 3);
    assert!(max_depth(RECORD) == 2);
    assert!(max_encoded_len(CHOICE) == 1 + 24);
    assert!(min_encoded_len(CHOICE) == 1);
    assert!(max_depth(CHOICE) == 1);
    assert!(max_encoded_len(THREE_WORDS) == 1 + 24);
    assert!(min_encoded_len(THREE_WORDS) == 1);
    assert!(max_depth(THREE_WORDS) == 1);
    assert!(max_encoded_len(PAIRS) == 1 + 2 * (1 + 3));
    assert!(max_depth(PAIRS) == 2);
    // A cap past one byte of length spends two.
    assert!(max_encoded_len(LABEL) == 2 + 300);
    assert!(max_depth(LABEL) == 0);
};

/// The widest value of a type encodes to exactly the folded bound, and the
/// encoder admits it at exactly the folded depth.
#[test]
fn the_folds_are_what_the_encoder_charges() {
    let widest = Record {
        a: 1,
        b: [2; 3],
        c: Some(3),
        d: (true, 4),
    };
    assert_eq!(to_vec(&widest).unwrap().len(), max_encoded_len(RECORD));
    assert!(to_vec_with_depth(&widest, max_depth(RECORD)).is_ok());
    assert!(matches!(
        to_vec_with_depth(&widest, max_depth(RECORD) - 1),
        Err(EncodeError::DepthExceeded { .. })
    ));

    let wide = Choice::Wide { held: 5, more: 6 };
    assert_eq!(to_vec(&wide).unwrap().len(), max_encoded_len(CHOICE));
    assert!(to_vec_with_depth(&wide, max_depth(CHOICE)).is_ok());
    assert!(to_vec_with_depth(&wide, max_depth(CHOICE) - 1).is_err());

    let words = vec![7u64; 3];
    assert_eq!(to_vec(&words).unwrap().len(), max_encoded_len(THREE_WORDS));
    assert!(to_vec_with_depth(&words, 1).is_ok());
    assert!(to_vec_with_depth(&words, 0).is_err());

    let pairs = BTreeMap::from([(1u8, Some(2u16)), (3, Some(4))]);
    assert_eq!(to_vec(&pairs).unwrap().len(), max_encoded_len(PAIRS));
    assert!(to_vec_with_depth(&pairs, 2).is_ok());
    assert!(to_vec_with_depth(&pairs, 1).is_err());

    let label = "x".repeat(300);
    assert_eq!(to_vec(&label).unwrap().len(), max_encoded_len(LABEL));
    assert!(to_vec_with_depth(&label, 0).is_ok());
}

/// The tree lowered to the recursive vocabulary, for the walk to answer
/// over. A name becomes an entry in the table and a reference to it; a cap
/// is dropped, because that vocabulary has nowhere to carry one.
fn lowered(node: &ShapeNode, types: &mut ShapeTable) -> TypeShape {
    match node {
        ShapeNode::Bool => TypeShape::Bool,
        ShapeNode::U8 => TypeShape::U8,
        ShapeNode::U16 => TypeShape::U16,
        ShapeNode::U32 => TypeShape::U32,
        ShapeNode::U64 => TypeShape::U64,
        ShapeNode::U128 => TypeShape::U128,
        ShapeNode::I8 => TypeShape::I8,
        ShapeNode::I16 => TypeShape::I16,
        ShapeNode::I32 => TypeShape::I32,
        ShapeNode::I64 => TypeShape::I64,
        ShapeNode::I128 => TypeShape::I128,
        ShapeNode::Text { .. } => TypeShape::Text,
        ShapeNode::ByteArray(width) => {
            TypeShape::ByteArray(u32::try_from(*width).expect("a test width fits"))
        }
        ShapeNode::Seq { element, .. } => TypeShape::Seq(Box::new(lowered(element, types))),
        ShapeNode::Set { element, .. } => TypeShape::Set(Box::new(lowered(element, types))),
        ShapeNode::Map { key, value, .. } => TypeShape::Map {
            key: Box::new(lowered(key, types)),
            value: Box::new(lowered(value, types)),
        },
        ShapeNode::Option(held) => TypeShape::Option(Box::new(lowered(held, types))),
        ShapeNode::Tuple(elements) => {
            TypeShape::Tuple(elements.iter().map(|e| lowered(e, types)).collect())
        }
        ShapeNode::Struct(fields) => TypeShape::Struct(
            fields
                .iter()
                .map(|(name, shape)| ShapeField {
                    name: (*name).to_owned(),
                    shape: lowered(shape, types),
                })
                .collect(),
        ),
        ShapeNode::Enum(variants) => TypeShape::Enum(
            variants
                .iter()
                .map(|(name, discriminant, content)| ShapeVariant {
                    name: (*name).to_owned(),
                    discriminant: *discriminant,
                    content: lowered(content, types),
                })
                .collect(),
        ),
        ShapeNode::Named { name, shape } => {
            let definition = lowered(shape, types);
            types.insert((*name).to_owned(), definition);
            TypeShape::Ref((*name).to_owned())
        }
    }
}

/// Where the recursive walk answers, the fold answers the same; where a
/// run leaves the walk without a widest value, the fold has one.
#[test]
fn the_folds_agree_with_the_recursive_walk() {
    for (node, closed) in [
        (RECORD, true),
        (CHOICE, true),
        (THREE_WORDS, false),
        (PAIRS, false),
        (LABEL, false),
    ] {
        let mut types = ShapeTable::new();
        let shape = lowered(node, &mut types);
        let mut walk = Resolution::of(&types);
        assert_eq!(
            walk.readable(&shape, MAX_SHAPE_DEPTH),
            Ok(max_depth(node)),
            "depth of {node:?}"
        );
        let most = walk.max_encoded_len(&shape, MAX_SHAPE_DEPTH).unwrap();
        if closed {
            assert_eq!(most, Some(max_encoded_len(node)), "width of {node:?}");
        } else {
            assert_eq!(most, None, "the walk has no width for {node:?}");
        }
    }
}

/// A generic impl composes its shape by naming its parameter's constant,
/// and a concrete type reads its bound off the composed tree — the form
/// the derive emits.
#[test]
fn a_generic_impl_composes_by_naming_its_parameter() {
    trait Shape {
        const NODE: &'static ShapeNode;
    }
    impl Shape for u8 {
        const NODE: &'static ShapeNode = &ShapeNode::U8;
    }
    impl Shape for u64 {
        const NODE: &'static ShapeNode = &ShapeNode::U64;
    }
    impl<T: Shape> Shape for Option<T> {
        const NODE: &'static ShapeNode = &ShapeNode::Option(T::NODE);
    }
    impl<T: Shape> Shape for Box<T> {
        const NODE: &'static ShapeNode = T::NODE;
    }
    struct Many<T, const N: usize>(std::marker::PhantomData<T>);
    impl<T: Shape, const N: usize> Shape for Many<T, N> {
        const NODE: &'static ShapeNode = &ShapeNode::Seq {
            cap: N,
            element: T::NODE,
        };
    }
    struct Composed {
        _a: u64,
        _b: Option<Box<u8>>,
        _c: Many<u64, 3>,
    }
    impl Shape for Composed {
        const NODE: &'static ShapeNode = &ShapeNode::Struct(&[
            ("a", <u64 as Shape>::NODE),
            ("b", <Option<Box<u8>> as Shape>::NODE),
            ("c", <Many<u64, 3> as Shape>::NODE),
        ]);
    }
    impl HborBound for Composed {
        const MAX_ENCODED_LEN: usize = max_encoded_len(Self::NODE);
        const MAX_DEPTH: usize = max_depth(Self::NODE);
    }
    const _: () = {
        assert!(<Composed as HborBound>::MAX_ENCODED_LEN == 8 + 2 + 25);
        assert!(<Composed as HborBound>::MAX_DEPTH == 2);
    };
    assert_eq!(<Composed as HborBound>::MAX_ENCODED_LEN, 35);
}
