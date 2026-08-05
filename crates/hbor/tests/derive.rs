//! The derive against hand-written impls, byte for byte.
//!
//! The phase bar for the derive is that it produces exactly what a careful
//! hand-written impl produces. Each type here is written twice — once
//! derived, once by hand — and the test asserts the two encodings are the
//! same bytes and that both decode the other's output. A derive that drifts
//! from the reference is caught as a byte difference rather than as a
//! downstream hash change.
//!
//! Every derived type also goes through the canonicity harness, so the
//! generated decoders are held to canonicity on the same terms as the
//! hand-written ones.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{
    DEFAULT_MAX_DEPTH, DecodeError, Decoder, EncodeError, Encoder, Hbor, HborDecode, HborEncode,
    HborWidth, assert_canonical, bounded, from_slice, from_slice_with_depth, to_vec,
    to_vec_with_depth,
};

// ---------------------------------------------------------------------------
// A record of scalars, against the impl it should match
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Header {
    height: u64,
    round: u32,
    proposer: u16,
    parent: [u8; 32],
    empty: bool,
}

/// What a careful author writes for [`Header`]: each field in declaration
/// order, nothing between them.
struct HeaderByHand(Header);

impl HborEncode for HeaderByHand {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.nested(&self.0.height)?;
        encoder.nested(&self.0.round)?;
        encoder.nested(&self.0.proposer)?;
        encoder.nested(&self.0.parent)?;
        encoder.nested(&self.0.empty)
    }
}

impl HborWidth for HeaderByHand {
    const MIN_ENCODED_LEN: usize = 8 + 4 + 2 + 32 + 1;
}

impl HborDecode for HeaderByHand {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self(Header {
            height: decoder.nested()?,
            round: decoder.nested()?,
            proposer: decoder.nested()?,
            parent: decoder.nested()?,
            empty: decoder.nested()?,
        }))
    }
}

const fn sample_header() -> Header {
    Header {
        height: 42,
        round: 3,
        proposer: 7,
        parent: [0xAB; 32],
        empty: false,
    }
}

#[test]
fn a_record_matches_its_hand_written_impl() {
    let value = sample_header();
    let derived = to_vec(&value).unwrap();
    let by_hand = to_vec(&HeaderByHand(value.clone())).unwrap();
    assert_eq!(derived, by_hand);

    // Each decoder accepts the other's bytes.
    assert_eq!(from_slice::<Header>(&by_hand).unwrap(), value);
    assert_eq!(from_slice::<HeaderByHand>(&derived).unwrap().0, value);

    assert_eq!(
        <Header as HborWidth>::MIN_ENCODED_LEN,
        <HeaderByHand as HborWidth>::MIN_ENCODED_LEN
    );
    assert_eq!(derived.len(), 47, "scalars carry no framing of their own");
}

// ---------------------------------------------------------------------------
// An enum, against the impl it should match
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
enum Body {
    Empty,
    Call(Vec<u8>),
    Publish { artifact: Vec<u8>, replaces: u64 },
}

struct BodyByHand(Body);

impl HborEncode for BodyByHand {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        match &self.0 {
            Body::Empty => encoder.write_u8(0),
            Body::Call(tree) => {
                encoder.write_u8(1);
                encoder.descend(|encoder| bounded::encode_bytes(encoder, tree))?;
            }
            Body::Publish { artifact, replaces } => {
                encoder.write_u8(2);
                encoder.descend(|encoder| bounded::encode_bytes(encoder, artifact))?;
                encoder.nested(replaces)?;
            }
        }
        Ok(())
    }
}

impl HborWidth for BodyByHand {
    const MIN_ENCODED_LEN: usize = 1;
}

impl HborDecode for BodyByHand {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let body = match decoder.read_u8()? {
            0 => Body::Empty,
            1 => Body::Call(decoder.descend(bounded::decode_bytes)?),
            2 => Body::Publish {
                artifact: decoder.descend(bounded::decode_bytes)?,
                replaces: decoder.nested()?,
            },
            other => return Err(DecodeError::InvalidDiscriminant(other)),
        };
        Ok(Self(body))
    }
}

#[test]
fn an_enum_matches_its_hand_written_impl() {
    for value in [
        Body::Empty,
        Body::Call(vec![1, 2, 3]),
        Body::Publish {
            artifact: vec![9; 40],
            replaces: 5,
        },
    ] {
        let derived = to_vec(&value).unwrap();
        assert_eq!(derived, to_vec(&BodyByHand(value.clone())).unwrap());
        assert_eq!(from_slice::<BodyByHand>(&derived).unwrap().0, value);
    }

    assert_eq!(
        <Body as HborWidth>::MIN_ENCODED_LEN,
        <BodyByHand as HborWidth>::MIN_ENCODED_LEN,
        "the discriminant plus the lightest variant, which is the unit one"
    );
}

#[test]
fn a_discriminant_naming_no_variant_rejects() {
    assert_eq!(
        from_slice::<Body>(&[3]),
        Err(DecodeError::InvalidDiscriminant(3))
    );
}

// ---------------------------------------------------------------------------
// Pinned discriminants
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
enum Pinned {
    #[hbor(discriminant = 7)]
    Seven,
    #[hbor(discriminant = 200)]
    TwoHundred(u8),
}

#[test]
fn a_pinned_discriminant_is_the_wire_byte() {
    assert_eq!(to_vec(&Pinned::Seven).unwrap(), vec![7]);
    assert_eq!(to_vec(&Pinned::TwoHundred(1)).unwrap(), vec![200, 1]);
    // The declaration index is not a fallback once a variant pins its byte.
    assert_eq!(
        from_slice::<Pinned>(&[0]),
        Err(DecodeError::InvalidDiscriminant(0))
    );
    assert_canonical(&Pinned::Seven);
    assert_canonical(&Pinned::TwoHundred(9));
}

// ---------------------------------------------------------------------------
// Transparent wrappers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
#[hbor(transparent)]
struct ValidatorId(u64);

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(transparent)]
struct Digest {
    inner: [u8; 32],
}

#[test]
fn a_transparent_wrapper_is_its_inner_type_on_the_wire() {
    assert_eq!(to_vec(&ValidatorId(9)).unwrap(), to_vec(&9u64).unwrap());
    assert_eq!(to_vec(&Digest { inner: [4; 32] }).unwrap(), vec![4u8; 32]);
    assert_eq!(
        <ValidatorId as HborWidth>::MIN_ENCODED_LEN,
        <u64 as HborWidth>::MIN_ENCODED_LEN
    );
    assert_canonical(&ValidatorId(9));
    assert_canonical(&Digest { inner: [4; 32] });
}

/// A wrapper is a name, not a layer: wrapping a value cannot change the
/// depth at which it decodes, or a rename would change which payloads a
/// consumer accepts.
#[test]
fn a_transparent_wrapper_charges_no_depth() {
    let wrapped = vec![vec![ValidatorId(1)]];
    let bare = vec![vec![1u64]];
    assert_eq!(to_vec(&wrapped).unwrap(), to_vec(&bare).unwrap());

    let bytes = to_vec(&wrapped).unwrap();
    let at_two = from_slice_with_depth::<Vec<Vec<ValidatorId>>>(&bytes, 2);
    let bare_at_two = from_slice_with_depth::<Vec<Vec<u64>>>(&bytes, 2);
    assert_eq!(at_two.is_ok(), bare_at_two.is_ok());
}

// ---------------------------------------------------------------------------
// Field caps
// ---------------------------------------------------------------------------

const MAX_MESSAGE: usize = 8;
const MAX_PEERS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Capped {
    #[hbor(max = MAX_MESSAGE)]
    message: Vec<u8>,
    #[hbor(max = MAX_PEERS)]
    peers: Vec<u64>,
    #[hbor(max = MAX_MESSAGE)]
    label: String,
    #[hbor(max = MAX_PEERS)]
    seen: BTreeSet<u16>,
    #[hbor(max = MAX_PEERS)]
    stakes: BTreeMap<u16, u64>,
}

fn sample_capped() -> Capped {
    Capped {
        message: vec![1, 2],
        peers: vec![10, 20],
        label: "ok".to_owned(),
        seen: BTreeSet::from([1, 2]),
        stakes: BTreeMap::from([(1, 100)]),
    }
}

/// A cap changes what is accepted, never what is written: the bytes of a
/// within-bounds value are identical to the same value in an uncapped field.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Uncapped {
    message: Vec<u8>,
    peers: Vec<u64>,
    label: String,
    seen: BTreeSet<u16>,
    stakes: BTreeMap<u16, u64>,
}

#[test]
fn a_cap_does_not_touch_the_wire_form() {
    let capped = sample_capped();
    let uncapped = Uncapped {
        message: capped.message.clone(),
        peers: capped.peers.clone(),
        label: capped.label.clone(),
        seen: capped.seen.clone(),
        stakes: capped.stakes.clone(),
    };
    assert_eq!(to_vec(&capped).unwrap(), to_vec(&uncapped).unwrap());
    assert_canonical(&capped);
}

#[test]
fn a_claim_past_a_cap_rejects() {
    let mut over = sample_capped();
    over.message = vec![0; MAX_MESSAGE + 1];
    // The encoder refuses to emit bytes its own decoder would reject, so the
    // oversized payload is built through the uncapped twin.
    let uncapped = Uncapped {
        message: over.message,
        peers: over.peers,
        label: over.label,
        seen: over.seen,
        stakes: over.stakes,
    };
    let bytes = to_vec(&uncapped).unwrap();
    assert_eq!(
        from_slice::<Capped>(&bytes),
        Err(DecodeError::BoundExceeded {
            max: MAX_MESSAGE,
            actual: MAX_MESSAGE + 1,
        })
    );
}

#[test]
fn encoding_a_value_grown_past_its_cap_refuses() {
    let mut over = sample_capped();
    over.peers = vec![0; MAX_PEERS + 1];
    assert_eq!(
        to_vec(&over),
        Err(EncodeError::BoundExceeded {
            field: "peers",
            actual: MAX_PEERS + 1,
            max: MAX_PEERS,
        })
    );
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// The shape the audit found behind most hand-written impls: a count in one
/// field that must agree with a length in another.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(validate = check_bundle)]
struct Bundle {
    signer_count: u16,
    signatures: Vec<[u8; 4]>,
}

fn check_bundle(bundle: &Bundle) -> Result<(), &'static str> {
    if usize::from(bundle.signer_count) == bundle.signatures.len() {
        Ok(())
    } else {
        Err("signer_count must equal the number of signatures")
    }
}

#[test]
fn a_predicate_rejects_at_the_wire_boundary() {
    let good = Bundle {
        signer_count: 2,
        signatures: vec![[1; 4], [2; 4]],
    };
    let bytes = to_vec(&good).unwrap();
    assert_eq!(from_slice::<Bundle>(&bytes).unwrap(), good);
    assert_canonical(&good);

    let bad = Bundle {
        signer_count: 3,
        signatures: vec![[1; 4]],
    };
    // Construction is not gated, so the mismatched value encodes; decoding
    // is where the predicate runs.
    let bad_bytes = to_vec(&bad).unwrap();
    assert_eq!(
        from_slice::<Bundle>(&bad_bytes),
        Err(DecodeError::FailedValidation(
            "signer_count must equal the number of signatures"
        ))
    );
}

// ---------------------------------------------------------------------------
// Generics, tuple structs, unit structs, nesting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Pair<T> {
    left: T,
    right: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Position(u32, u32);

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Marker;

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Block {
    header: Header,
    body: Body,
    votes: Vec<ValidatorId>,
    tags: BTreeMap<ValidatorId, Position>,
}

#[test]
fn generic_positional_and_nested_shapes_round_trip() {
    assert_canonical(&Pair {
        left: 1u32,
        right: 2,
    });
    assert_canonical(&Pair {
        left: vec![1u8],
        right: vec![],
    });
    assert_canonical(&Position(3, 4));
    assert_canonical(&Marker);

    let block = Block {
        header: sample_header(),
        body: Body::Call(vec![7, 7]),
        votes: vec![ValidatorId(1), ValidatorId(2)],
        tags: BTreeMap::from([(ValidatorId(1), Position(0, 0))]),
    };
    assert_canonical(&block);
}

#[test]
fn a_unit_struct_occupies_no_bytes() {
    assert_eq!(to_vec(&Marker).unwrap(), Vec::<u8>::new());
    assert_eq!(<Marker as HborWidth>::MIN_ENCODED_LEN, 0);
}

/// A container divides the remaining input by its element's minimum to bound
/// a claimed length, so an overstated minimum would reject valid payloads and
/// an understated one would weaken the bound.
#[test]
fn a_derived_minimum_is_the_sum_of_its_fields() {
    assert_eq!(<Position as HborWidth>::MIN_ENCODED_LEN, 8);
    assert_eq!(
        <Bundle as HborWidth>::MIN_ENCODED_LEN,
        2 + 1,
        "a count plus an empty sequence's length byte"
    );
    let shortest = to_vec(&Position(0, 0)).unwrap();
    assert_eq!(shortest.len(), <Position as HborWidth>::MIN_ENCODED_LEN);
}

/// The audit case: identical wire bytes, one field written as `Vec<u8>` and
/// one as an alias of it. The alias declines the fast path, so this is the
/// cross-spelling pair — both must accept and refuse at every cap.
#[test]
fn depth_charge_is_independent_of_spelling() {
    type AliasedBytes = Vec<u8>;

    #[derive(Debug, Clone, PartialEq, Eq, Hbor)]
    struct Literal {
        data: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hbor)]
    struct Aliased {
        data: AliasedBytes,
    }

    for data in [vec![], vec![1u8, 2, 3]] {
        let literal = Literal { data: data.clone() };
        let aliased = Aliased { data };
        let bytes = to_vec(&literal).unwrap();
        assert_eq!(bytes, to_vec(&aliased).unwrap());

        for cap in 0..4 {
            assert_eq!(
                from_slice_with_depth::<Literal>(&bytes, cap).is_ok(),
                from_slice_with_depth::<Aliased>(&bytes, cap).is_ok(),
                "decode at cap {cap}"
            );
            assert_eq!(
                to_vec_with_depth(&literal, cap).is_ok(),
                to_vec_with_depth(&aliased, cap).is_ok(),
                "encode at cap {cap}"
            );
        }
    }
}

/// A cap changes what a field accepts, never what depth it charges: capped
/// and uncapped twins of every collection shape agree at every cap.
#[test]
fn depth_charge_is_independent_of_caps() {
    let capped = sample_capped();
    let uncapped = Uncapped {
        message: capped.message.clone(),
        peers: capped.peers.clone(),
        label: capped.label.clone(),
        seen: capped.seen.clone(),
        stakes: capped.stakes.clone(),
    };
    let bytes = to_vec(&capped).unwrap();
    for cap in 0..5 {
        assert_eq!(
            from_slice_with_depth::<Capped>(&bytes, cap).is_ok(),
            from_slice_with_depth::<Uncapped>(&bytes, cap).is_ok(),
            "decode at cap {cap}"
        );
        assert_eq!(
            to_vec_with_depth(&capped, cap).is_ok(),
            to_vec_with_depth(&uncapped, cap).is_ok(),
            "encode at cap {cap}"
        );
    }
}

#[test]
fn the_derive_agrees_with_the_reference_at_a_shared_depth() {
    let block = Block {
        header: sample_header(),
        body: Body::Empty,
        votes: vec![],
        tags: BTreeMap::new(),
    };
    let bytes = to_vec_with_depth(&block, DEFAULT_MAX_DEPTH).unwrap();
    assert!(from_slice_with_depth::<Block>(&bytes, DEFAULT_MAX_DEPTH).is_ok());
}
