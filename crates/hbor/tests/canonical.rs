//! Canonicity over a generated corpus.
//!
//! The unit tests beside each impl pin the interesting hand-picked values.
//! This runs the same harness — round trip, trailing byte, every truncation,
//! every single-byte mutation — over arbitrary values of every shape the
//! crate can encode, including the nested combinations where a length field
//! of one type sits beside the discriminant of another.
//!
//! Values are kept small on purpose: the harness is quadratic in encoded
//! length, and canonicity violations live at field boundaries, which a short
//! value has just as many of per byte.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::assert_canonical;
use proptest::collection::{btree_map, btree_set, vec};
use proptest::option;
use proptest::prelude::{Strategy, any, proptest};

proptest! {
    #[test]
    fn unsigned_integers(a: u8, b: u16, c: u32, d: u64, e: u128) {
        assert_canonical(&a);
        assert_canonical(&b);
        assert_canonical(&c);
        assert_canonical(&d);
        assert_canonical(&e);
    }

    #[test]
    fn signed_integers(a: i8, b: i16, c: i32, d: i64, e: i128) {
        assert_canonical(&a);
        assert_canonical(&b);
        assert_canonical(&c);
        assert_canonical(&d);
        assert_canonical(&e);
    }

    #[test]
    fn booleans_and_byte_arrays(flag: bool, key: [u8; 16], digest: [u8; 32]) {
        assert_canonical(&flag);
        assert_canonical(&key);
        assert_canonical(&digest);
    }

    #[test]
    fn options(present: Option<u32>, nested: Option<Option<u8>>, of_seq: Option<Vec<u8>>) {
        assert_canonical(&present);
        assert_canonical(&nested);
        assert_canonical(&of_seq);
    }

    #[test]
    fn tuples(pair: (u8, u64), triple: (bool, [u8; 8], u16)) {
        assert_canonical(&pair);
        assert_canonical(&triple);
    }

    #[test]
    fn sequences(bytes in vec(any::<u8>(), 0..24), words in vec(any::<u32>(), 0..8)) {
        assert_canonical(&bytes);
        assert_canonical(&words);
    }

    /// A length field whose width changes is where a non-minimal encoding
    /// would hide, so the corpus straddles the one-to-two byte boundary.
    #[test]
    fn sequences_across_a_length_width_boundary(len in 120usize..136) {
        assert_canonical(&vec![7u8; len]);
    }

    #[test]
    fn strings(text in ".{0,24}") {
        assert_canonical(&text);
    }

    #[test]
    fn ordered_collections(
        set in btree_set(any::<u16>(), 0..8),
        map in btree_map(any::<u8>(), any::<u64>(), 0..8),
    ) {
        assert_canonical(&set);
        assert_canonical(&map);
    }

    #[test]
    fn nested_shapes(
        seq_of_seq in vec(vec(any::<u8>(), 0..4), 0..4),
        seq_of_opt in vec(option::of(any::<u16>()), 0..6),
        map_of_seq in btree_map(any::<u8>(), vec(any::<u8>(), 0..4), 0..4),
        set_of_pair in btree_set((any::<u8>(), any::<u8>()), 0..6),
    ) {
        assert_canonical(&seq_of_seq);
        assert_canonical(&seq_of_opt);
        assert_canonical(&map_of_seq);
        assert_canonical(&set_of_pair);
    }

    /// Every container stacked at once — a sequence of pairs whose second
    /// element is an optional sequence — so a length field, a discriminant,
    /// and a fixed-width scalar all sit adjacent for the mutation pass.
    #[test]
    fn stacked_containers(tree in stacked()) {
        assert_canonical(&tree);
    }
}

fn stacked() -> impl Strategy<Value = Vec<(u8, Option<Vec<u8>>)>> {
    vec((any::<u8>(), option::of(vec(any::<u8>(), 0..4))), 0..4)
}

/// Empty-value encodings are the shortest byte strings a type has, and the
/// place a truncation check has the least room to work — pinned explicitly
/// rather than left to the generator.
#[test]
fn empty_values_are_canonical() {
    assert_canonical(&Vec::<u8>::new());
    assert_canonical(&Vec::<Vec<u8>>::new());
    assert_canonical(&String::new());
    assert_canonical(&BTreeSet::<u8>::new());
    assert_canonical(&BTreeMap::<u8, u8>::new());
    assert_canonical(&Option::<Vec<u8>>::None);
    assert_canonical(&());
    assert_canonical(&[0u8; 0]);
}

/// Extremes of each integer width, where a sign bit or a carry would show.
#[test]
fn integer_extremes_are_canonical() {
    assert_canonical(&(u8::MIN, u8::MAX));
    assert_canonical(&(i8::MIN, i8::MAX));
    assert_canonical(&(u64::MIN, u64::MAX));
    assert_canonical(&(i64::MIN, i64::MAX));
    assert_canonical(&u128::MAX);
    assert_canonical(&i128::MIN);
}
