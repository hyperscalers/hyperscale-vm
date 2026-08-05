//! Signing preimages, against the real envelope this replaces.
//!
//! [`Envelope`] mirrors the protocol's signed transaction envelope field for
//! field. Its preimage is written twice — derived, and by hand in the same
//! terms — and the two must be the same bytes, on the same footing as the
//! wire codecs in `derive.rs`.
//!
//! The rest of the file pins the properties the hand-written preimage
//! builders in the protocol argue for one type at a time. Under a canonical
//! encoding they are consequences, not claims: a preimage that is the
//! canonical encoding of a value is injective because the encoding is.

use hyperscale_hbor::{
    DEFAULT_MAX_DEPTH, EncodeError, Encoder, Hbor, HborSigned, assert_canonical, bounded, to_vec,
};

/// A named change to one field, for the coverage sweep below.
type FieldEdit = (&'static str, fn(&mut Envelope));

const MAX_TREE: usize = 4096;
const MAX_MESSAGE: usize = 1024;

/// What an envelope asks the chain for.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
enum Body {
    Call(#[hbor(max = MAX_TREE)] Vec<u8>),
    Publish(#[hbor(max = MAX_TREE)] Vec<u8>),
}

/// One bound subintent's signature.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct SubintentSig {
    public_key: [u8; 32],
    signature: [u8; 64],
}

/// The signed transaction envelope: what it asks for and the signing-time
/// choices, under the composer's signature.
///
/// The composer's own key and signature cannot be part of what the signature
/// covers, and are the only two fields held out.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-vm-envelope-v1")]
struct Envelope {
    body: Body,
    subintent_sigs: Vec<SubintentSig>,
    fee_payer: [u8; 16],
    max_fee: u128,
    gas_limit: u64,
    validity_start_ms: u64,
    validity_end_ms: u64,
    #[hbor(max = MAX_MESSAGE)]
    message: Vec<u8>,
    #[hbor(unsigned)]
    signer: [u8; 32],
    #[hbor(unsigned)]
    signature: [u8; 64],
}

/// What a careful author writes for [`Envelope`]'s preimage: the framed
/// domain, then every signed field in declaration order.
fn envelope_preimage_by_hand(envelope: &Envelope) -> Result<Vec<u8>, EncodeError> {
    let mut buffer = Vec::new();
    let mut encoder = Encoder::new(&mut buffer, DEFAULT_MAX_DEPTH);
    encoder.write_sized(Envelope::SIGNING_DOMAIN)?;
    encoder.nested(&envelope.body)?;
    encoder.nested(&envelope.subintent_sigs)?;
    encoder.nested(&envelope.fee_payer)?;
    encoder.nested(&envelope.max_fee)?;
    encoder.nested(&envelope.gas_limit)?;
    encoder.nested(&envelope.validity_start_ms)?;
    encoder.nested(&envelope.validity_end_ms)?;
    bounded::check_encoded_len("message", envelope.message.len(), MAX_MESSAGE)?;
    encoder.descend(|encoder| bounded::encode_bytes(encoder, &envelope.message))?;
    Ok(buffer)
}

fn sample() -> Envelope {
    Envelope {
        body: Body::Call(vec![1, 2, 3]),
        subintent_sigs: vec![SubintentSig {
            public_key: [0x11; 32],
            signature: [0x22; 64],
        }],
        fee_payer: [0x33; 16],
        max_fee: 1_000_000,
        gas_limit: 500_000,
        validity_start_ms: 1_700_000_000_000,
        validity_end_ms: 1_700_000_060_000,
        message: b"hello".to_vec(),
        signer: [0x44; 32],
        signature: [0x55; 64],
    }
}

#[test]
fn the_derived_preimage_matches_a_hand_written_one() {
    let envelope = sample();
    assert_eq!(
        envelope.signing_bytes().unwrap(),
        envelope_preimage_by_hand(&envelope).unwrap()
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
    let envelope = sample();
    let mut resigned = envelope.clone();
    resigned.signer = [0x99; 32];
    resigned.signature = [0xAA; 64];

    assert_eq!(
        envelope.signing_bytes().unwrap(),
        resigned.signing_bytes().unwrap(),
        "changing the signature must not change what it covers"
    );
    assert_ne!(
        to_vec(&envelope).unwrap(),
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
    let mutate: [FieldEdit; 8] = [
        ("body", |e| e.body = Body::Publish(vec![1, 2, 3])),
        ("subintent_sigs", |e| e.subintent_sigs.clear()),
        ("fee_payer", |e| e.fee_payer = [0x77; 16]),
        ("max_fee", |e| e.max_fee += 1),
        ("gas_limit", |e| e.gas_limit += 1),
        ("validity_start_ms", |e| e.validity_start_ms += 1),
        ("validity_end_ms", |e| e.validity_end_ms += 1),
        ("message", |e| e.message.push(b'!')),
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

/// The discriminant is signed content: the same bytes read as a call graph
/// and as an artifact are different transactions, and the enum tag is what
/// says which.
#[test]
fn the_body_discriminant_is_covered() {
    let mut call = sample();
    call.body = Body::Call(vec![9, 9]);
    let mut publish = sample();
    publish.body = Body::Publish(vec![9, 9]);
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
    left.message = b"ab".to_vec();
    left.subintent_sigs.clear();

    let mut right = sample();
    right.message = b"a".to_vec();
    right.subintent_sigs.clear();
    right.body = Body::Call(vec![1, 2, 3, b'b']);

    assert_ne!(
        left.signing_bytes().unwrap(),
        right.signing_bytes().unwrap()
    );
}

/// A preimage begins with its domain and never with content, so no value's
/// preimage is a prefix of another's by construction.
#[test]
fn a_preimage_starts_with_its_framed_domain() {
    let envelope = sample();
    let bytes = envelope.signing_bytes().unwrap();
    let domain = Envelope::SIGNING_DOMAIN;
    let framed = to_vec(&domain.to_vec()).unwrap();
    assert!(bytes.starts_with(&framed));
}
