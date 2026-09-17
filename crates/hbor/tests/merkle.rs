//! Field-level proofs against a shape with a field of every kind.
//!
//! [`Order`] is the stand-in shape the signing tests use. Here the question
//! is whether a holder of only its root can be shown one field, and only
//! that field.

use hyperscale_hbor::hash::TestHasher;
use hyperscale_hbor::merkle::{Chunked, prove, root_of, sequence_chunks, verify};
use hyperscale_hbor::{Hbor, HborMerkle, to_vec};

const MAX_ITEM: usize = 4096;
const MAX_NOTE: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hbor, HborMerkle)]
#[hbor(merkle_domain = "test-item-v1")]
enum Item {
    Goods(#[hbor(max = MAX_ITEM)] Vec<u8>),
    Service(#[hbor(max = MAX_ITEM)] Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Endorsement {
    public_key: [u8; 32],
    signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor, HborMerkle)]
#[hbor(merkle_domain = "test-order-v1")]
struct Order {
    item: Item,
    endorsements: Vec<Endorsement>,
    buyer: [u8; 16],
    budget: u128,
    quotas: Vec<u64>,
    priority_bp: u32,
    opens_ms: u64,
    closes_ms: u64,
    #[hbor(max = MAX_NOTE)]
    note: Vec<u8>,
    signer: [u8; 32],
    signature: [u8; 64],
}

/// Field positions, in declaration order. A leaf index is a position in the
/// type, so naming them here is what makes the assertions below readable.
const ITEM: usize = 0;
const ENDORSEMENTS: usize = 1;
const BUYER: usize = 2;
const BUDGET: usize = 3;
const QUOTAS: usize = 4;
const NOTE: usize = 8;
const FIELD_COUNT: usize = 11;

fn sample() -> Order {
    Order {
        item: Item::Goods(vec![1, 2, 3]),
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
        note: b"hello".to_vec(),
        signer: [0x44; 32],
        signature: [0x55; 64],
    }
}

/// Leaf order is declaration order. A tree whose leaf positions did not match
/// the type's field order would still root and still verify — it would just
/// prove the wrong field, which is why this is pinned rather than assumed.
#[test]
fn leaf_order_is_declaration_order() {
    let order = sample();
    let leaves = order.chunks().unwrap();
    assert_eq!(leaves[ITEM], to_vec(&order.item).unwrap());
    assert_eq!(leaves[ENDORSEMENTS], to_vec(&order.endorsements).unwrap());
    assert_eq!(leaves[BUYER], to_vec(&order.buyer).unwrap());
    assert_eq!(leaves[BUDGET], to_vec(&order.budget).unwrap());
    assert_eq!(leaves[QUOTAS], to_vec(&order.quotas).unwrap());
    assert_eq!(leaves[NOTE], to_vec(&order.note).unwrap());
}

#[test]
fn every_field_proves_against_the_root() {
    let hasher = TestHasher;
    let order = sample();
    let root = order.merkle_root(&hasher).unwrap();
    let leaves = order.chunks().unwrap();
    assert_eq!(leaves.len(), FIELD_COUNT);

    for (index, leaf) in leaves.iter().enumerate() {
        let proof = order.prove(&hasher, index).unwrap().expect("a field");
        assert!(
            verify(&hasher, Order::MERKLE_DOMAIN, root, leaf, &proof),
            "field {index} failed to verify"
        );
    }
}

/// The point of a tree rather than a hash: the verifier is shown one field's
/// bytes and the path, and learns nothing of the rest.
#[test]
fn a_proof_carries_one_field_and_a_path() {
    let hasher = TestHasher;
    let order = sample();
    let root = order.merkle_root(&hasher).unwrap();

    let proof = order.prove(&hasher, BUDGET).unwrap().unwrap();
    let claimed = to_vec(&order.budget).unwrap();
    assert!(verify(
        &hasher,
        Order::MERKLE_DOMAIN,
        root,
        &claimed,
        &proof
    ));

    // Four levels for eleven leaves, and nothing else.
    assert_eq!(proof.siblings.len(), 4);
    assert_eq!(proof.leaf_count, FIELD_COUNT);
}

#[test]
fn an_altered_field_fails_against_the_root() {
    let hasher = TestHasher;
    let order = sample();
    let root = order.merkle_root(&hasher).unwrap();
    let proof = order.prove(&hasher, QUOTAS).unwrap().unwrap();

    assert!(verify(
        &hasher,
        Order::MERKLE_DOMAIN,
        root,
        &to_vec(&order.quotas).unwrap(),
        &proof
    ));
    let mut raised = order.quotas;
    raised[1] += 1;
    assert!(!verify(
        &hasher,
        Order::MERKLE_DOMAIN,
        root,
        &to_vec(&raised).unwrap(),
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
    altered.item = Item::Service(vec![1, 2, 3]);
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.endorsements.clear();
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.buyer = [0x77; 16];
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.budget += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.quotas[1] += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.priority_bp += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.opens_ms += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.closes_ms += 1;
    assert_ne!(altered.merkle_root(&hasher).unwrap(), base);

    let mut altered = sample();
    altered.note.push(b'!');
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
    let order = sample();
    let joined: Vec<u8> = order.chunks().unwrap().concat();
    assert_eq!(joined, to_vec(&order).unwrap());
}

/// A proof for one field must not verify when presented at another field's
/// position, even with that field's bytes.
#[test]
fn a_proof_does_not_transfer_between_fields() {
    let hasher = TestHasher;
    let order = sample();
    let root = order.merkle_root(&hasher).unwrap();

    let proof = order.prove(&hasher, BUYER).unwrap().unwrap();
    let other = to_vec(&order.note).unwrap();
    assert!(!verify(&hasher, Order::MERKLE_DOMAIN, root, &other, &proof));

    let message_proof = order.prove(&hasher, NOTE).unwrap().unwrap();
    assert!(!verify(
        &hasher,
        Order::MERKLE_DOMAIN,
        root,
        &to_vec(&order.buyer).unwrap(),
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
    let item = Item::Service(vec![9; 64]);
    let root = item.merkle_root(&hasher).unwrap();

    let leaves = item.chunks().unwrap();
    assert_eq!(leaves.len(), 2, "a discriminant leaf and one field");

    let tag_proof = item.prove(&hasher, 0).unwrap().unwrap();
    assert!(verify(
        &hasher,
        Item::MERKLE_DOMAIN,
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
    let call = Item::Goods(vec![7, 7]);
    let publish = Item::Service(vec![7, 7]);
    assert_ne!(
        call.merkle_root(&hasher).unwrap(),
        publish.merkle_root(&hasher).unwrap()
    );
}

// ---------------------------------------------------------------------------
// Sequences
// ---------------------------------------------------------------------------

/// The shape receipt trees and settled-transaction roots want: a root over a list,
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

/// A `#[hbor(skip)]` variant field is omitted from the wire, so the tree
/// omits it too — else `merkle_root(decode(encode(x))) != merkle_root(x)`
/// once the skipped value is non-default, and the leaves stop partitioning
/// the encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hbor, HborMerkle)]
#[hbor(merkle_domain = "test-skip-v1")]
enum Tagged {
    Kept {
        seen: u32,
        #[hbor(skip)]
        ignored: u32,
    },
}

#[test]
fn a_skipped_variant_field_is_not_a_leaf() {
    let hasher = TestHasher;
    let with_value = Tagged::Kept {
        seen: 7,
        ignored: 99,
    };
    // The wire omits the skipped field, so a value carrying one encodes
    // exactly as one that defaulted it.
    let defaulted = Tagged::Kept {
        seen: 7,
        ignored: 0,
    };
    assert_eq!(to_vec(&with_value).unwrap(), to_vec(&defaulted).unwrap());
    assert_eq!(
        with_value.merkle_root(&hasher).unwrap(),
        defaulted.merkle_root(&hasher).unwrap(),
    );

    // And the leaves are exactly the encoding, with nothing invented for
    // the skipped field.
    let joined: Vec<u8> = with_value.chunks().unwrap().concat();
    assert_eq!(joined, to_vec(&with_value).unwrap());
}
