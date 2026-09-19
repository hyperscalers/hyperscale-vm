//! The capped collections against the bare ones they encode as.
//!
//! The bar is that a cap changes nothing on the wire: a `Capped<Vec<T>, N>`
//! writes the bytes a `Vec<T>` writes, a `Bytes<N>` the bytes the derive's
//! fast path writes for a `Vec<u8>`, and a `Text<N>` the bytes a `String`
//! writes. What the type adds is where the cap is held — at construction,
//! and at decode before anything is allocated.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_hbor::{
    Bytes, Capped, DecodeError, Hbor, HborShape, Overflow, ShapeNode, Text, assert_canonical,
    from_slice, from_slice_with_depth, to_vec,
};

type Words = Capped<Vec<u32>, 3>;
type Members = Capped<BTreeSet<u8>, 2>;
type Rows = Capped<BTreeMap<u8, u16>, 2>;

/// Every capped form encodes exactly as its bare form, and decodes back.
#[test]
fn a_cap_changes_nothing_on_the_wire() {
    let words = Words::new(vec![1, 2, 3]).unwrap();
    assert_eq!(to_vec(&words).unwrap(), to_vec(&vec![1u32, 2, 3]).unwrap());
    assert_eq!(
        from_slice::<Words>(&to_vec(&words).unwrap()).unwrap(),
        words
    );
    assert_canonical(&words);

    let members = Members::new(BTreeSet::from([7, 9])).unwrap();
    assert_eq!(
        to_vec(&members).unwrap(),
        to_vec(&BTreeSet::from([7u8, 9])).unwrap()
    );
    assert_canonical(&members);

    let rows = Rows::new(BTreeMap::from([(1, 10), (2, 20)])).unwrap();
    assert_eq!(
        to_vec(&rows).unwrap(),
        to_vec(&BTreeMap::from([(1u8, 10u16), (2, 20)])).unwrap()
    );
    assert_canonical(&rows);

    let bytes = Bytes::<4>::new(vec![1, 2, 3, 4]).unwrap();
    assert_eq!(
        to_vec(&bytes).unwrap(),
        to_vec(&vec![1u8, 2, 3, 4]).unwrap()
    );
    assert_canonical(&bytes);

    let text = Text::<5>::new("héllo".chars().take(4).collect()).unwrap();
    assert_eq!(to_vec(&text).unwrap(), to_vec(&text.to_string()).unwrap());
    assert_canonical(&text);
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Fast {
    payload: Vec<u8>,
    tail: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Typed {
    payload: Bytes<8>,
    tail: u8,
}

/// A `Bytes<N>` field writes what the derive's `Vec<u8>` fast path writes,
/// and the two decode each other's output.
#[test]
fn bytes_match_the_fast_path() {
    let fast = Fast {
        payload: vec![9; 8],
        tail: 1,
    };
    let typed = Typed {
        payload: Bytes::new(vec![9; 8]).unwrap(),
        tail: 1,
    };
    let bytes = to_vec(&fast).unwrap();
    assert_eq!(bytes, to_vec(&typed).unwrap());
    assert_eq!(from_slice::<Typed>(&bytes).unwrap(), typed);
    assert_eq!(from_slice::<Fast>(&to_vec(&typed).unwrap()).unwrap(), fast);
    assert_canonical(&typed);
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Wrapped {
    maybe: Option<Words>,
    shared: Arc<Members>,
    boxed: Box<Rows>,
    label: Option<Text<3>>,
    raw: Arc<Bytes<2>>,
}

/// A capped type under a wrapper is the wrapper over the bare type.
#[test]
fn a_cap_reaches_through_a_wrapper() {
    let wrapped = Wrapped {
        maybe: Some(Words::new(vec![4]).unwrap()),
        shared: Arc::new(Members::new(BTreeSet::from([1])).unwrap()),
        boxed: Box::new(Rows::new(BTreeMap::from([(3, 30)])).unwrap()),
        label: Some(Text::new("ab".into()).unwrap()),
        raw: Arc::new(Bytes::new(vec![0, 1]).unwrap()),
    };
    assert_canonical(&wrapped);
    let bytes = to_vec(&wrapped).unwrap();
    assert_eq!(from_slice::<Wrapped>(&bytes).unwrap(), wrapped);
}

/// A claimed length past the cap is refused at decode, before anything is
/// built, naming the cap.
#[test]
fn a_decode_past_the_cap_is_refused() {
    let four = to_vec(&vec![1u32, 2, 3, 4]).unwrap();
    assert_eq!(
        from_slice::<Words>(&four),
        Err(DecodeError::BoundExceeded { max: 3, actual: 4 })
    );
    let three = to_vec(&BTreeSet::from([1u8, 2, 3])).unwrap();
    assert_eq!(
        from_slice::<Members>(&three),
        Err(DecodeError::BoundExceeded { max: 2, actual: 3 })
    );
    let three = to_vec(&BTreeMap::from([(1u8, 1u16), (2, 2), (3, 3)])).unwrap();
    assert_eq!(
        from_slice::<Rows>(&three),
        Err(DecodeError::BoundExceeded { max: 2, actual: 3 })
    );
    let five = to_vec(&vec![0u8; 5]).unwrap();
    assert_eq!(
        from_slice::<Bytes<4>>(&five),
        Err(DecodeError::BoundExceeded { max: 4, actual: 5 })
    );
    let six = to_vec(&"abcdef".to_owned()).unwrap();
    assert_eq!(
        from_slice::<Text<5>>(&six),
        Err(DecodeError::BoundExceeded { max: 5, actual: 6 })
    );
}

/// A value past the cap cannot be built: the constructors and the
/// fallible inserts are where the cap is held.
#[test]
fn a_value_past_the_cap_cannot_be_built() {
    assert_eq!(
        Words::new(vec![1, 2, 3, 4]),
        Err(Overflow { actual: 4, max: 3 })
    );
    let mut words = Words::empty();
    for word in 0..3 {
        words.push(word).unwrap();
    }
    assert_eq!(words.push(3), Err(Overflow { actual: 4, max: 3 }));
    assert_eq!(words.len(), 3);

    let mut members = Members::default();
    assert!(members.insert(1).unwrap());
    assert!(members.insert(2).unwrap());
    // A member already present takes no room.
    assert_eq!(members.insert(2), Ok(false));
    assert_eq!(members.insert(3), Err(Overflow { actual: 3, max: 2 }));

    let mut rows = Rows::default();
    assert_eq!(rows.insert(1, 10), Ok(None));
    assert_eq!(rows.insert(2, 20), Ok(None));
    // A key already present is replaced without room for a new one.
    assert_eq!(rows.insert(2, 21), Ok(Some(20)));
    assert_eq!(rows.insert(3, 30), Err(Overflow { actual: 3, max: 2 }));

    assert_eq!(
        Bytes::<2>::try_from(&[1u8, 2, 3][..]),
        Err(Overflow { actual: 3, max: 2 })
    );
    // The cap on text is bytes: two characters of three bytes each do
    // not fit in five.
    assert_eq!(
        Text::<5>::try_from("日本"),
        Err(Overflow { actual: 6, max: 5 })
    );
    assert!(Text::<6>::try_from("日本").is_ok());
}

/// A capped type describes as the run it encodes as, under its cap.
#[test]
fn a_capped_type_shapes_as_a_run_under_its_cap() {
    assert_eq!(
        Words::NODE,
        &ShapeNode::Seq {
            cap: 3,
            element: &ShapeNode::U32
        }
    );
    assert_eq!(
        Members::NODE,
        &ShapeNode::Set {
            cap: 2,
            element: &ShapeNode::U8
        }
    );
    assert_eq!(
        Rows::NODE,
        &ShapeNode::Map {
            cap: 2,
            key: &ShapeNode::U8,
            value: &ShapeNode::U16
        }
    );
    assert_eq!(
        Bytes::<4>::NODE,
        &ShapeNode::Seq {
            cap: 4,
            element: &ShapeNode::U8
        }
    );
    assert_eq!(Text::<5>::NODE, &ShapeNode::Text { cap: 5 });
}

/// A capped run charges the level its bare form charges, and text none.
#[test]
fn a_cap_charges_the_bare_depth() {
    let words = to_vec(&Words::new(vec![1]).unwrap()).unwrap();
    assert!(from_slice_with_depth::<Words>(&words, 1).is_ok());
    assert!(from_slice_with_depth::<Words>(&words, 0).is_err());
    let bytes = to_vec(&Bytes::<4>::new(vec![1]).unwrap()).unwrap();
    assert!(from_slice_with_depth::<Bytes<4>>(&bytes, 1).is_ok());
    assert!(from_slice_with_depth::<Bytes<4>>(&bytes, 0).is_err());
    let text = to_vec(&Text::<5>::new("a".into()).unwrap()).unwrap();
    assert!(from_slice_with_depth::<Text<5>>(&text, 0).is_ok());
}

/// What is offered mutably is what cannot reach the cap: an element
/// replaced in place or moved changes no length, and a removal leaves a
/// value under any cap the longer one met. The lengthening writers are
/// the fallible ones above; these are the rest of the surface, and none
/// of them can put a value past its type.
#[test]
fn the_mutable_surface_cannot_lengthen_a_value() {
    let mut words = Words::from_array([3, 1, 2]);
    assert_eq!(words.len(), 3, "at the cap to begin with");

    words.swap(0, 2);
    words.sort_by_key(|word| *word);
    for word in &mut words {
        *word += 10;
    }
    *words.get_mut(0).expect("an element at the front") += 100;
    words[1] = 99;
    words.retain(|_| true);
    assert_eq!(words.len(), 3, "nothing offered here lengthens");
    assert_eq!(words, [111u32, 99, 13]);

    // Removal, which a shorter value survives under any cap.
    assert_eq!(words.remove(0), 111);
    assert_eq!(words.pop(), Some(13));
    words.truncate(0);
    words.clear();
    assert!(words.is_empty());

    // The same for a byte string: an index and an iterator, no growth.
    let mut bytes = Bytes::<3>::from_array([1, 2, 3]);
    bytes[0] = 9;
    for byte in &mut bytes {
        *byte += 1;
    }
    assert_eq!(bytes, [10u8, 3, 4]);
    bytes.truncate(1);
    assert_eq!(bytes.len(), 1);

    // A map's values are replaceable in place; its keys are not, so the
    // cap stays the insert's business.
    let mut rows = Rows::default();
    rows.insert(1, 10).expect("room for the first");
    for value in rows.values_mut() {
        *value += 1;
    }
    *rows.get_mut(&1).expect("the value at 1") += 1;
    assert_eq!(rows.get(&1), Some(&12));
}
