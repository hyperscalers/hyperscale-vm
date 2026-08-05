//! The canonicity theorem, fuzzed: every byte string either rejects or
//! decodes to a value that re-encodes to exactly itself.
//!
//! The harness in `hbor::canonical` checks this construction-level — around
//! the encodings of known values, where non-minimal lengths and unsorted
//! keys live. This lane drops the "around known values" qualifier: the input
//! is any byte string at all, decoded against a zoo of shapes that exercises
//! every piece of wire machinery the crate has. Same promotion policy as the
//! sibling target: a finding is checked into the seeded corpus as a unit
//! test before the fix merges.

#![no_main]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use hyperscale_hbor::{Hbor, HborDecode, HborEncode, from_slice, from_slice_with_depth, to_vec};
use libfuzzer_sys::fuzz_target;

/// One shape per wire mechanism: discriminants (pinned and positional),
/// scalars, the byte fast path beside a capped field, UTF-8, ordered
/// collections, nesting, options, and a cross-field predicate.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
enum Zoo {
    Unit,
    Scalars(u8, u32, u128, i64, bool),
    Bytes {
        #[hbor(max = 64)]
        data: Vec<u8>,
        tail: u16,
    },
    Text(String),
    Ordered {
        set: BTreeSet<u16>,
        map: BTreeMap<u8, Vec<u8>>,
    },
    Nested(Vec<Option<(u8, Vec<u16>)>>),
    #[hbor(discriminant = 200)]
    Pinned([u8; 32]),
}

/// A cross-field predicate, so the validation path sees hostile input too.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(validate = check_counted)]
struct Counted {
    count: u16,
    items: Vec<u32>,
}

fn check_counted(counted: &Counted) -> Result<(), &'static str> {
    if usize::from(counted.count) == counted.items.len() {
        Ok(())
    } else {
        Err("count must equal the number of items")
    }
}

/// A tight cap beside the default: whatever the tight decoder accepts, the
/// loose one must accept identically — a cap only ever shrinks the set.
const TIGHT_DEPTH: usize = 4;

fn check<T>(input: &[u8])
where
    T: HborEncode + HborDecode + PartialEq + Debug,
{
    if let Ok(value) = from_slice::<T>(input) {
        let re_encoded = to_vec(&value).expect("a decoded value re-encodes");
        assert_eq!(re_encoded, input, "two byte strings for one {value:?}");
    }
    if let Ok(value) = from_slice_with_depth::<T>(input, TIGHT_DEPTH) {
        let loose = from_slice::<T>(input).expect("a tighter cap admits no extra payloads");
        assert_eq!(value, loose);
    }
}

fuzz_target!(|data: &[u8]| {
    check::<Zoo>(data);
    check::<Vec<Zoo>>(data);
    check::<Counted>(data);
    check::<BTreeMap<u16, Zoo>>(data);
});
