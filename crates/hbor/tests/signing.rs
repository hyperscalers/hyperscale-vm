//! Signing preimages, against a shape that exercises every feature the
//! derive offers.
//!
//! [`Order`] is a signed message with an enum, a list of structs, scalars,
//! a bounded byte field and two unsigned trailing fields — a stand-in shape
//! rather than any protocol type. Its preimage is written twice — derived,
//! and by hand in the same terms — and the two must be the same bytes, on
//! the same footing as the wire codecs in `derive.rs`.
//!
//! The rest of the file pins the properties a hand-written preimage builder
//! argues for one type at a time. Under a canonical encoding they are
//! consequences, not claims: a preimage that is the canonical encoding of a
//! value is injective because the encoding is.

use hyperscale_hbor::{
    Bytes, DEFAULT_MAX_DEPTH, EncodeError, Encoder, Hbor, HborSigned, HborSignedWith,
    assert_canonical, to_vec,
};

/// A named change to one field, for the coverage sweep below.
type FieldEdit = (&'static str, fn(&mut Order));

const MAX_ITEM: usize = 4096;
const MAX_NOTE: usize = 1024;

/// What an order is for.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
enum Item {
    Goods(Bytes<MAX_ITEM>),
    Service(Bytes<MAX_ITEM>),
}

/// One party's endorsement of the order, carried inside what is signed.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Endorsement {
    public_key: [u8; 32],
    signature: [u8; 64],
}

/// A signed order: what it is for and the terms it is placed under, under
/// the placing party's signature.
///
/// The signer's own key and signature cannot be part of what the signature
/// covers, and are the only two fields held out.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "test-order-v1")]
struct Order {
    item: Item,
    endorsements: Vec<Endorsement>,
    buyer: [u8; 16],
    budget: u128,
    quotas: Vec<u64>,
    priority_bp: u32,
    opens_ms: u64,
    closes_ms: u64,
    note: Bytes<MAX_NOTE>,
    #[hbor(unsigned)]
    signer: [u8; 32],
    #[hbor(unsigned)]
    signature: [u8; 64],
}

/// What a careful author writes for [`Order`]'s preimage: the framed
/// domain, then every signed field in declaration order.
fn envelope_preimage_by_hand(order: &Order) -> Result<Vec<u8>, EncodeError> {
    let mut buffer = Vec::new();
    let mut encoder = Encoder::new(&mut buffer, DEFAULT_MAX_DEPTH);
    encoder.write_sized(Order::SIGNING_DOMAIN)?;
    encoder.nested(&order.item)?;
    encoder.nested(&order.endorsements)?;
    encoder.nested(&order.buyer)?;
    encoder.nested(&order.budget)?;
    encoder.nested(&order.quotas)?;
    encoder.nested(&order.priority_bp)?;
    encoder.nested(&order.opens_ms)?;
    encoder.nested(&order.closes_ms)?;
    encoder.nested(&order.note)?;
    Ok(buffer)
}

fn sample() -> Order {
    Order {
        item: Item::Goods(Bytes::from_array([1, 2, 3])),
        endorsements: vec![Endorsement {
            public_key: [0x11; 32],
            signature: [0x22; 64],
        }],
        buyer: [0x33; 16],
        budget: 1_000_000,
        quotas: vec![300_000, 200_000],
        priority_bp: 250,
        opens_ms: 1_700_000_000_000,
        closes_ms: 1_700_000_060_000,
        note: Bytes::from_array(*b"hello"),
        signer: [0x44; 32],
        signature: [0x55; 64],
    }
}

#[test]
fn the_derived_preimage_matches_a_hand_written_one() {
    let order = sample();
    assert_eq!(
        order.signing_bytes().unwrap(),
        envelope_preimage_by_hand(&order).unwrap()
    );
}

#[test]
fn the_envelope_still_round_trips_on_the_wire() {
    assert_canonical(&sample());
}

/// The two fields a signature cannot cover ride the wire and are absent from
/// the preimage — the whole point of the marking.
#[test]
fn unsigned_fields_leave_the_preimage_but_not_the_wire() {
    let order = sample();
    let mut resigned = order.clone();
    resigned.signer = [0x99; 32];
    resigned.signature = [0xAA; 64];

    assert_eq!(
        order.signing_bytes().unwrap(),
        resigned.signing_bytes().unwrap(),
        "changing the signature must not change what it covers"
    );
    assert_ne!(
        to_vec(&order).unwrap(),
        to_vec(&resigned).unwrap(),
        "the signature is still transmitted"
    );
}

/// Every other field is covered. This is the property that decays silently
/// when a preimage is maintained by hand: a field added to the message and
/// forgotten in the builder is unauthenticated content nobody notices.
#[test]
fn every_signed_field_changes_the_preimage() {
    let base = sample().signing_bytes().unwrap();
    let mutate: [FieldEdit; 9] = [
        ("item", |e| {
            e.item = Item::Service(Bytes::from_array([1, 2, 3]));
        }),
        ("endorsements", |e| e.endorsements.clear()),
        ("buyer", |e| e.buyer = [0x77; 16]),
        ("budget", |e| e.budget += 1),
        ("quotas", |e| e.quotas[1] += 1),
        ("priority_bp", |e| e.priority_bp += 1),
        ("opens_ms", |e| e.opens_ms += 1),
        ("closes_ms", |e| e.closes_ms += 1),
        ("note", |e| e.note.push(b'!').expect("under the note cap")),
    ];
    for (field, apply) in mutate {
        let mut altered = sample();
        apply(&mut altered);
        assert_ne!(
            altered.signing_bytes().unwrap(),
            base,
            "{field} is signed content and must move the preimage"
        );
    }
}

/// The discriminant is signed content: the same bytes read as goods and
/// as a service are different orders, and the enum tag is what
/// says which.
#[test]
fn the_body_discriminant_is_covered() {
    let mut call = sample();
    call.item = Item::Goods(Bytes::from_array([9, 9]));
    let mut publish = sample();
    publish.item = Item::Service(Bytes::from_array([9, 9]));
    assert_ne!(
        call.signing_bytes().unwrap(),
        publish.signing_bytes().unwrap()
    );
}

// ---------------------------------------------------------------------------
// Domain framing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "vote-v1")]
struct VoteV1 {
    payload: Vec<u8>,
}

/// A domain that extends another by a digit — the shape a versioned domain
/// grows into on its second version.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "vote-v10")]
struct VoteV10 {
    payload: Vec<u8>,
}

/// Unframed, `"vote-v1"` followed by content beginning `'0'` is `"vote-v10"`
/// followed by the rest, and a signature gathered under one domain verifies
/// under the other. The length prefix is what makes the boundary readable.
#[test]
fn a_domain_that_prefixes_another_cannot_collide() {
    let short = VoteV1 {
        payload: b"0abc".to_vec(),
    };
    let long = VoteV10 {
        payload: b"abc".to_vec(),
    };

    let short_bytes = short.signing_bytes().unwrap();
    let long_bytes = long.signing_bytes().unwrap();
    assert_ne!(short_bytes, long_bytes);

    // The collision the framing prevents, spelled out: without the lengths,
    // the two preimages are the same byte string.
    let unframed = |domain: &[u8], payload: &[u8]| {
        let mut out = domain.to_vec();
        out.extend_from_slice(payload);
        out
    };
    assert_eq!(
        unframed(VoteV1::SIGNING_DOMAIN, &short.payload),
        unframed(VoteV10::SIGNING_DOMAIN, &long.payload)
    );
}

/// Two types carrying identical content under different domains commit to
/// different byte strings, so a signature for one never verifies the other.
#[test]
fn distinct_domains_separate_identical_content() {
    let payload = b"same".to_vec();
    let one = VoteV1 {
        payload: payload.clone(),
    };
    let other = VoteV10 { payload };
    assert_ne!(one.signing_bytes().unwrap(), other.signing_bytes().unwrap());
}

// ---------------------------------------------------------------------------
// Injectivity
// ---------------------------------------------------------------------------

/// The property the hand-written builders exist to establish, and the reason
/// they length-prefix some fields and not others: two distinct signed
/// contents must not share a preimage.
///
/// Here it is inherited rather than argued. A preimage is the canonical
/// encoding of the signed subset, so two preimages agree only when that
/// subset does — which is exactly canonicity, already property-tested.
#[test]
fn moving_bytes_between_adjacent_fields_changes_the_preimage() {
    let mut left = sample();
    left.note = Bytes::from_array(*b"ab");
    left.endorsements.clear();

    let mut right = sample();
    right.note = Bytes::from_array(*b"a");
    right.endorsements.clear();
    right.item = Item::Goods(Bytes::from_array([1, 2, 3, b'b']));

    assert_ne!(
        left.signing_bytes().unwrap(),
        right.signing_bytes().unwrap()
    );
}

/// A preimage begins with its domain and never with content, so no value's
/// preimage is a prefix of another's by construction.
#[test]
fn a_preimage_starts_with_its_framed_domain() {
    let order = sample();
    let bytes = order.signing_bytes().unwrap();
    let domain = Order::SIGNING_DOMAIN;
    let framed = to_vec(&domain.to_vec()).unwrap();
    assert!(bytes.starts_with(&framed));
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Session state both sides hold: which network the session is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
struct NetworkTag(u8);

/// A vote whose preimage mixes in the session's network ahead of its own
/// fields, so the network never has to be a struct field.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "ctx-vote-v1", signing_context = NetworkTag)]
struct CtxVote {
    height: u64,
    payload: Bytes<MAX_NOTE>,
    #[hbor(unsigned)]
    signature: [u8; 64],
}

/// The same message with the context spelled as a leading field, under the
/// same domain — the spelling the context replaces, and the definition of
/// what its preimage must be.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "ctx-vote-v1")]
struct LeadingFieldVote {
    network: NetworkTag,
    height: u64,
    payload: Bytes<MAX_NOTE>,
    #[hbor(unsigned)]
    signature: [u8; 64],
}

fn ctx_sample() -> CtxVote {
    CtxVote {
        height: 42,
        payload: Bytes::from_array(*b"payload"),
        signature: [0x66; 64],
    }
}

/// The context is a fixed type encoded after the framed domain, so the
/// preimage is byte-equal to the twin that carries it as a leading field —
/// which is what lets injectivity carry over without a new argument.
#[test]
fn a_context_preimage_equals_its_leading_field_spelling() {
    let vote = ctx_sample();
    let twin = LeadingFieldVote {
        network: NetworkTag(7),
        height: vote.height,
        payload: vote.payload.clone(),
        signature: vote.signature,
    };
    assert_eq!(
        vote.signing_bytes(&NetworkTag(7)).unwrap(),
        twin.signing_bytes().unwrap()
    );
}

/// The context is covered: the same value signed in two sessions commits to
/// two byte strings, which is what makes a cross-session replay fail.
#[test]
fn the_context_moves_the_preimage() {
    let vote = ctx_sample();
    assert_ne!(
        vote.signing_bytes(&NetworkTag(1)).unwrap(),
        vote.signing_bytes(&NetworkTag(2)).unwrap()
    );
}

/// `unsigned` composes with a context exactly as without one.
#[test]
fn unsigned_fields_leave_a_context_preimage() {
    let vote = ctx_sample();
    let mut resigned = vote.clone();
    resigned.signature = [0x99; 64];
    assert_eq!(
        vote.signing_bytes(&NetworkTag(7)).unwrap(),
        resigned.signing_bytes(&NetworkTag(7)).unwrap()
    );
}
