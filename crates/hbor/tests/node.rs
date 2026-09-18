//! The static shape tree and the bounds folded off it.
//!
//! Three things hold the folds honest: the figures are constants, so a
//! type's bound is stated beside its shape; they agree with the encoder,
//! which is what charges the levels and writes the bytes; and the table a
//! tree is declared into measures every node the same.

use std::collections::BTreeMap;

use hyperscale_hbor::node::{max_depth, max_encoded_len, min_encoded_len};
use hyperscale_hbor::{
    Capped, EncodeError, Hbor, HborBound, HborShape, ShapeNode, ShapeTable, to_vec,
    to_vec_with_depth,
};

#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
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
#[derive(Debug, PartialEq, Eq, Hbor, HborShape)]
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

/// The derive states the tree written out above, and the bound a type
/// carries is the fold over it.
const _: () = {
    assert!(<Record as HborBound>::MAX_ENCODED_LEN == max_encoded_len(RECORD));
    assert!(<Record as HborBound>::MAX_DEPTH == max_depth(RECORD));
    assert!(<Choice as HborBound>::MAX_ENCODED_LEN == max_encoded_len(CHOICE));
    assert!(<Choice as HborBound>::MAX_DEPTH == max_depth(CHOICE));
    assert!(<Capped<Vec<u64>, 3> as HborBound>::MAX_ENCODED_LEN == max_encoded_len(THREE_WORDS));
};

#[test]
fn the_derive_states_the_tree_the_type_is() {
    assert_eq!(<Record as HborShape>::NODE, RECORD);
    assert_eq!(<Choice as HborShape>::NODE, CHOICE);
    assert_eq!(<Capped<Vec<u64>, 3> as HborShape>::NODE, THREE_WORDS);
}

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

/// A tree declared into a table measures what the folds state: the two
/// derivations — the constant beside the type, and the pass over the
/// published array — answer the same for every node.
#[test]
fn the_table_measures_what_the_folds_state() {
    for node in [RECORD, CHOICE, THREE_WORDS, PAIRS, LABEL] {
        let mut table = ShapeTable::new();
        let id = table.declare(node).unwrap();
        assert_eq!(table.most(id), max_encoded_len(node), "width of {node:?}");
        assert_eq!(table.least(id), min_encoded_len(node), "least of {node:?}");
        assert_eq!(table.depth(id), max_depth(node), "depth of {node:?}");
        assert!(table.matches(id, node));
    }
}

/// A generic impl composes its shape by naming its parameter's constant,
/// and a concrete type reads its bound off the composed tree — the form
/// the derive emits.
#[test]
fn a_generic_impl_composes_by_naming_its_parameter() {
    #[derive(Hbor, HborShape)]
    struct Composed<T> {
        a: u64,
        b: Option<Box<T>>,
        c: Capped<Vec<T>, 3>,
    }
    const _: () = {
        assert!(<Composed<u8> as HborBound>::MAX_ENCODED_LEN == 8 + 2 + 4);
        assert!(<Composed<u8> as HborBound>::MAX_DEPTH == 2);
        assert!(<Composed<u64> as HborBound>::MAX_ENCODED_LEN == 8 + 9 + 25);
    };
    assert_eq!(
        <Composed<u8> as HborShape>::NODE,
        &ShapeNode::Named {
            name: "composed",
            shape: &ShapeNode::Struct(&[
                ("a", &ShapeNode::U64),
                ("b", &ShapeNode::Option(&ShapeNode::U8)),
                (
                    "c",
                    &ShapeNode::Seq {
                        cap: 3,
                        element: &ShapeNode::U8
                    }
                ),
            ]),
        }
    );
}
