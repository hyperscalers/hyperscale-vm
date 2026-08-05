//! Field-level proofs against the real envelope shape.
//!
//! [`Envelope`] mirrors the protocol's signed transaction envelope, the same
//! shape the signing tests use. Here the question is whether a holder of only
//! its root can be shown one field, and only that field.

use hyperscale_hbor::hash::TestHasher;
use hyperscale_hbor::merkle::{Chunked, prove, root_of, sequence_chunks, verify};
use hyperscale_hbor::{Hbor, HborMerkle, to_vec};

const MAX_TREE: usize = 4096;
const MAX_MESSAGE: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hbor, HborMerkle)]
#[hbor(merkle_domain = "test-body-v1")]
enum Body {
    Call(#[hbor(max = MAX_TREE)] Vec<u8>),
    Publish(#[hbor(max = MAX_TREE)] Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct SubintentSig {
    public_key: [u8; 32],
    signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor, HborMerkle)]
#[hbor(merkle_domain = "test-envelope-v1")]
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
    signer: [u8; 32],
    signature: [u8; 64],
}

/// Field positions, in declaration order. A leaf index is a position in the
/// type, so naming them here is what makes the assertions below readable.
const BODY: usize = 0;
const SUBINTENT_SIGS: usize = 1;
const FEE_PAYER: usize = 2;
const MAX_FEE: usize = 3;
const GAS_LIMIT: usize = 4;
const MESSAGE: usize = 7;
const FIELD_COUNT: usize = 10;

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

/// Leaf order is declaration order. A tree whose leaf positions did not match
/// the type's field order would still root and still verify — it would just
/// prove the wrong field, which is why this is pinned rather than assumed.
#[test]
fn leaf_order_is_declaration_order() {
    let envelope = sample();
    let leaves = envelope.chunks().unwrap();
    assert_eq!(leaves[BODY], to_vec(&envelope.body).unwrap());
    assert_eq!(
        leaves[SUBINTENT_SIGS],
        to_vec(&envelope.subintent_sigs).unwrap()
    );
    assert_eq!(leaves[FEE_PAYER], to_vec(&envelope.fee_payer).unwrap());
    assert_eq!(leaves[MAX_FEE], to_vec(&envelope.max_fee).unwrap());
    assert_eq!(leaves[GAS_LIMIT], to_vec(&envelope.gas_limit).unwrap());
    assert_eq!(leaves[MESSAGE], to_vec(&envelope.message).unwrap());
}

#[test]
fn every_field_proves_against_the_root() {
    let hasher = TestHasher;
    let envelope = sample();
    let root = envelope.merkle_root(&hasher).unwrap();
    let leaves = envelope.chunks().unwrap();
    assert_eq!(leaves.len(), FIELD_COUNT);

    for (index, leaf) in leaves.iter().enumerate() {
        let proof = envelope.prove(&hasher, index).unwrap().expect("a field");
        assert!(
            verify(&hasher, Envelope::MERKLE_DOMAIN, root, leaf, &proof),
            "field {index} failed to verify"
        );
    }
}

/// The point of a tree rather than a hash: the verifier is shown one field's
/// bytes and the path, and learns nothing of the rest.
#[test]
fn a_proof_carries_one_field_and_a_path() {
    let hasher = TestHasher;
    let envelope = sample();
    let root = envelope.merkle_root(&hasher).unwrap();

    let proof = envelope.prove(&hasher, MAX_FEE).unwrap().unwrap();
    let claimed = to_vec(&envelope.max_fee).unwrap();
    assert!(verify(
        &hasher,
        Envelope::MERKLE_DOMAIN,
        root,
        &claimed,
        &proof
    ));

    // Four levels for ten leaves, and nothing else.
    assert_eq!(proof.siblings.len(), 4);
    assert_eq!(proof.leaf_count, FIELD_COUNT);
}

#[test]
fn an_altered_field_fails_against_the_root() {
    let hasher = TestHasher;
    let envelope = sample();
    let root = envelope.merkle_root(&hasher).unwrap();
    let proof = envelope.prove(&hasher, GAS_LIMIT).unwrap().unwrap();

    assert!(verify(
        &hasher,
        Envelope::MERKLE_DOMAIN,
        root,
        &to_vec(&envelope.gas_limit).unwrap(),
        &proof
    ));
    assert!(!verify(
        &hasher,
        Envelope::MERKLE_DOMAIN,
        root,
        &to_vec(&(envelope.gas_limit + 1)).unwrap(),
        &proof
    ));
}

/// Every leaf, altered one at a time: the root must move for each, or some
/// field is outside what the root covers.
#[test]
fn every_field_is_covered_by_the_root() {
    let hasher = TestHasher;
    let base = sample().merkle_root(&hasher).unwrap();

    let mut altered = sample();
    altered.body = Body::Publish(vec![1, 2, 3]);
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.subintent_sigs.clear();
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.fee_payer = [0x77; 16];
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.max_fee += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.gas_limit += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.validity_start_ms += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.validity_end_ms += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.message.push(b'!');
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.signer = [0x99; 32];
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.signature = [0xAA; 64];
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);
}

/// A field's bytes inside its parent are its standalone encoding, because
/// the encoding is schema-external and carries no context. So the leaves are
/// exactly the parent's bytes, split at the field boundaries — nothing
/// invented for the tree, nothing left out of it.
#[test]
fn the_leaves_partition_the_encoding() {
    let envelope = sample();
    let joined: Vec<u8> = envelope.chunks().unwrap().concat();
    assert_eq!(joined, to_vec(&envelope).unwrap());
}

/// A proof for one field must not verify when presented at another field's
/// position, even with that field's bytes.
#[test]
fn a_proof_does_not_transfer_between_fields() {
    let hasher = TestHasher;
    let envelope = sample();
    let root = envelope.merkle_root(&hasher).unwrap();

    let proof = envelope.prove(&hasher, FEE_PAYER).unwrap().unwrap();
    let other = to_vec(&envelope.message).unwrap();
    assert!(!verify(
        &hasher,
        Envelope::MERKLE_DOMAIN,
        root,
        &other,
        &proof
    ));

    let message_proof = envelope.prove(&hasher, MESSAGE).unwrap().unwrap();
    assert!(!verify(
        &hasher,
        Envelope::MERKLE_DOMAIN,
        root,
        &to_vec(&envelope.fee_payer).unwrap(),
        &message_proof
    ));
}

#[test]
fn a_field_index_past_the_type_has_no_proof() {
    let hasher = TestHasher;
    assert!(sample().prove(&hasher, FIELD_COUNT).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// The discriminant is its own leaf, so which variant a value is can be shown
/// without showing what the variant holds.
#[test]
fn a_variant_proves_without_its_content() {
    let hasher = TestHasher;
    let body = Body::Publish(vec![9; 64]);
    let root = body.merkle_root(&hasher).unwrap();

    let leaves = body.chunks().unwrap();
    assert_eq!(leaves.len(), 2, "a discriminant leaf and one field");

    let tag_proof = body.prove(&hasher, 0).unwrap().unwrap();
    assert!(verify(
        &hasher,
        Body::MERKLE_DOMAIN,
        root,
        &leaves[0],
        &tag_proof
    ));
    assert_eq!(
        leaves[0],
        to_vec(&1u8).unwrap(),
        "Publish is discriminant 1"
    );
}

/// Two variants carrying identical content are different values, and the
/// discriminant leaf is what says so.
#[test]
fn variants_with_the_same_content_differ_at_the_root() {
    let hasher = TestHasher;
    let call = Body::Call(vec![7, 7]);
    let publish = Body::Publish(vec![7, 7]);
    assert_ne!(
        call.merkle_root(&hasher).unwrap(),
        publish.merkle_root(&hasher).unwrap()
    );
}

// ---------------------------------------------------------------------------
// Sequences
// ---------------------------------------------------------------------------

/// The shape receipt trees and settled-wave roots want: a root over a list,
/// with a proof per element. A sequence has no domain of its own, so the
/// caller names one at the root — which is what keeps a receipt list and a
/// witness list of identical hashes apart.
const RECEIPTS: &[u8] = b"test-receipts-v1";

#[test]
fn a_sequence_proves_per_element() {
    let hasher = TestHasher;
    let receipts: Vec<[u8; 32]> = (0..7).map(|i| [i; 32]).collect();
    let leaves = sequence_chunks(&receipts).unwrap();
    let root = root_of(&hasher, RECEIPTS, &leaves);

    for (index, receipt) in receipts.iter().enumerate() {
        let proof = prove(&hasher, &leaves, index).unwrap();
        assert!(verify(
            &hasher,
            RECEIPTS,
            root,
            &to_vec(receipt).unwrap(),
            &proof
        ));
    }

    let stranger = [0xFFu8; 32];
    let proof = prove(&hasher, &leaves, 3).unwrap();
    assert!(!verify(
        &hasher,
        RECEIPTS,
        root,
        &to_vec(&stranger).unwrap(),
        &proof
    ));
}

/// A shorter list must not share a root with a longer one, whatever the
/// padding happens to be — the leaf count is mixed into the root for this.
#[test]
fn sequences_of_different_lengths_differ_at_the_root() {
    let hasher = TestHasher;
    let roots: Vec<_> = (0..=8)
        .map(|n| {
            let list: Vec<u8> = (0..n).collect();
            root_of(&hasher, RECEIPTS, &sequence_chunks(&list).unwrap())
        })
        .collect();
    for (i, a) in roots.iter().enumerate() {
        for (j, b) in roots.iter().enumerate() {
            assert!(i == j || a != b, "lists of {i} and {j} share a root");
        }
    }
}

// ---------------------------------------------------------------------------
// Type binding
// ---------------------------------------------------------------------------

/// The audit case, inverted: two types whose fields encode to identical
/// bytes, and a sequence of the same arity, must all root differently — and
/// a field proof gathered against one must not verify against another.
#[test]
fn identical_bytes_under_different_types_do_not_share_a_root() {
    #[derive(Debug, Clone, PartialEq, Eq, Hbor, HborMerkle)]
    #[hbor(merkle_domain = "test-transfer-v1")]
    struct Transfer {
        from: [u8; 32],
        to: [u8; 32],
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hbor, HborMerkle)]
    #[hbor(merkle_domain = "test-approval-v1")]
    struct Approval {
        owner: [u8; 32],
        spender: [u8; 32],
    }

    let hasher = TestHasher;
    let transfer = Transfer {
        from: [1; 32],
        to: [2; 32],
    };
    let approval = Approval {
        owner: [1; 32],
        spender: [2; 32],
    };
    let list = vec![[1u8; 32], [2u8; 32]];

    assert_eq!(transfer.chunks().unwrap(), approval.chunks().unwrap());

    let transfer_root = transfer.merkle_root(&hasher).unwrap();
    let approval_root = approval.merkle_root(&hasher).unwrap();
    let list_root = root_of(&hasher, RECEIPTS, &sequence_chunks(&list).unwrap());
    assert_ne!(transfer_root, approval_root);
    assert_ne!(transfer_root, list_root);
    assert_ne!(approval_root, list_root);

    // The substitution the domain exists to stop: a `Transfer` root
    // presented where an `Approval` root is expected. The trees are
    // structurally identical, so without the domain in the root this would
    // verify.
    let proof = transfer.prove(&hasher, 0).unwrap().unwrap();
    let bytes = to_vec(&transfer.from).unwrap();
    assert!(verify(
        &hasher,
        Transfer::MERKLE_DOMAIN,
        transfer_root,
        &bytes,
        &proof
    ));
    assert!(!verify(
        &hasher,
        Approval::MERKLE_DOMAIN,
        transfer_root,
        &bytes,
        &proof
    ));
    assert!(!verify(
        &hasher,
        Transfer::MERKLE_DOMAIN,
        approval_root,
        &bytes,
        &proof
    ));
}
