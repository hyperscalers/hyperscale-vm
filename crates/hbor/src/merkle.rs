//! Merkleization: a value's identity as a tree over its own fields.
//!
//! A hash over a whole encoding proves the whole value or nothing. A tree
//! over the fields proves one field to someone holding only the root — which
//! is what receipt trees, settled-transaction roots, and witness roots are all
//! building by hand, each in its own shape, beside an encoding that could
//! have defined it.
//!
//! Here a leaf is one field's canonical encoding. Because the encoding is
//! schema-external, a field's bytes inside its parent *are* its standalone
//! encoding — there is no tag or length that only makes sense in context — so
//! the leaves partition the parent's bytes exactly, with nothing invented for
//! the tree and nothing left out of it.
//!
//! # One leaf per field
//!
//! Not one leaf per fixed-width group. Grouping scalars would shrink the tree
//! and cost the property the tree exists for: proving `height` would reveal
//! `round`. A type that wants its scalars atomic can put them in a nested
//! struct, which is one leaf.
//!
//! # Shape
//!
//! Leaves are hashed under a leaf domain, internal nodes under a node domain,
//! so no internal node's preimage can be read as a leaf. Odd levels pad with
//! a hash under a third domain rather than by duplicating the last node — the
//! duplication trick makes distinct trees share a root. The leaf count is
//! mixed into the root, so a one-leaf tree is not its own leaf and two
//! different counts cannot agree.
//!
//! # Depth is flat
//!
//! Leaves are the top-level fields. A field that is itself a composite is one
//! leaf holding its whole encoding, not a subtree. Proving inside it means
//! proving that field, then proving within its own root — composition the
//! caller does, and which nothing here hides.
//!
//! # The root binds a type, not just bytes
//!
//! A per-type domain is mixed into the root beside the leaf count. Without
//! it, two types whose fields encode to the same bytes share a root, and a
//! field proof against one verifies against the other — the same substitution
//! a signing domain exists to prevent, one seam over. A derived type names
//! its domain explicitly; a bare sequence has no identity of its own, so
//! sequences root through the free functions with a caller-named domain
//! rather than through a blanket impl whose one shared domain would let
//! every same-shaped sequence in the system collide.

use crate::hash::{Hash32, Hasher};
use crate::{EncodeError, HborEncode, to_vec};

/// Domain for leaf hashes.
pub const DOMAIN_LEAF: &[u8] = b"hbor-merkle-leaf-v1";
/// Domain for internal node hashes.
pub const DOMAIN_NODE: &[u8] = b"hbor-merkle-node-v1";
/// Domain for the padding hash on an odd level.
pub const DOMAIN_PAD: &[u8] = b"hbor-merkle-pad-v1";
/// Domain for the root, which mixes in the leaf count.
pub const DOMAIN_ROOT: &[u8] = b"hbor-merkle-root-v1";

/// A type whose identity is a tree over its own fields.
///
/// Derived by `#[derive(HborMerkle)]` with `#[hbor(merkle_domain = "...")]`.
/// A type that derives it has its root as its identity: hashing its encoding
/// separately would be a second hash for one value, which is the thing this
/// encoding exists to avoid.
pub trait Chunked {
    /// What this type's roots are for.
    ///
    /// Mixed into the root, so two types whose fields encode to the same
    /// bytes still root differently and a proof gathered against one type
    /// never verifies against another. Two types, or two versions of one
    /// type, must not share a domain — the same discipline a signing domain
    /// carries.
    const MERKLE_DOMAIN: &'static [u8];

    /// This value's leaves, in declaration order, each the canonical
    /// encoding of one field or element.
    ///
    /// # Errors
    ///
    /// [`EncodeError`], as encoding the fields.
    fn chunks(&self) -> Result<Vec<Vec<u8>>, EncodeError>;

    /// This value's merkle root, under the type's domain.
    ///
    /// # Errors
    ///
    /// [`EncodeError`], as [`Chunked::chunks`].
    fn merkle_root(&self, hasher: &dyn Hasher) -> Result<Hash32, EncodeError> {
        Ok(root_of(hasher, Self::MERKLE_DOMAIN, &self.chunks()?))
    }

    /// A proof that the leaf at `index` sits under this value's root.
    ///
    /// Returns `None` when `index` names no leaf. The domain enters at
    /// verification, not here: a proof is a path through the tree, and the
    /// root is where the tree is bound to its type.
    ///
    /// # Errors
    ///
    /// [`EncodeError`], as [`Chunked::chunks`].
    fn prove(&self, hasher: &dyn Hasher, index: usize) -> Result<Option<Proof>, EncodeError> {
        Ok(prove(hasher, &self.chunks()?, index))
    }
}

/// The leaves of a sequence: one per element, in order.
///
/// The chunking half of what the blanket `Vec` impl would have been. The
/// missing half is deliberate: a bare sequence has no domain of its own, so
/// its root comes from [`root_of`] with a domain the caller names — a
/// receipt tree and a witness list of the same hashes must not agree.
///
/// # Errors
///
/// [`EncodeError`], as encoding the elements.
pub fn sequence_chunks<T: HborEncode>(elements: &[T]) -> Result<Vec<Vec<u8>>, EncodeError> {
    elements.iter().map(|element| to_vec(element)).collect()
}

/// What a holder of the root needs to check one leaf: where it sits, how many
/// leaves there were, and the hashes along the way.
///
/// The leaf count is part of the proof because it is part of the root. A
/// proof that claimed a different count would rebuild a different root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Which leaf this proves.
    pub index: usize,
    /// How many leaves the tree had.
    pub leaf_count: usize,
    /// The sibling hash at each level, from the leaf upward.
    pub siblings: Vec<Hash32>,
}

/// The root over `chunks`, under `domain`.
#[must_use]
pub fn root_of(hasher: &dyn Hasher, domain: &[u8], chunks: &[Vec<u8>]) -> Hash32 {
    let mut level: Vec<Hash32> = chunks.iter().map(|chunk| leaf(hasher, chunk)).collect();
    if level.is_empty() {
        return finish(hasher, domain, pad(hasher), 0);
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(pad(hasher));
        }
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| node(hasher, pair[0], pair[1]))
            .collect();
    }
    finish(hasher, domain, level[0], chunks.len())
}

/// A proof for the leaf at `index`, or `None` when `index` names no leaf.
#[must_use]
pub fn prove(hasher: &dyn Hasher, chunks: &[Vec<u8>], index: usize) -> Option<Proof> {
    if index >= chunks.len() {
        return None;
    }
    let mut level: Vec<Hash32> = chunks.iter().map(|chunk| leaf(hasher, chunk)).collect();
    let mut position = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(pad(hasher));
        }
        siblings.push(level[position ^ 1]);
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| node(hasher, pair[0], pair[1]))
            .collect();
        position /= 2;
    }
    Some(Proof {
        index,
        leaf_count: chunks.len(),
        siblings,
    })
}

/// Whether `leaf_bytes` sits at `proof.index` under `root`.
///
/// The walk is driven by the proof's own leaf count rather than by the length
/// of its sibling list, and then the two must agree — a proof carrying extra
/// or missing siblings is rejected rather than silently walking a tree of a
/// different height. The verifier names the domain, which is the point: it
/// says which type's root it believes it holds, and a proof gathered against
/// any other type rebuilds a different root.
#[must_use]
pub fn verify(
    hasher: &dyn Hasher,
    domain: &[u8],
    root: Hash32,
    leaf_bytes: &[u8],
    proof: &Proof,
) -> bool {
    if proof.index >= proof.leaf_count {
        return false;
    }
    let mut current = leaf(hasher, leaf_bytes);
    let mut position = proof.index;
    let mut width = proof.leaf_count;
    let mut used = 0;
    while width > 1 {
        let Some(sibling) = proof.siblings.get(used) else {
            return false;
        };
        current = if position.is_multiple_of(2) {
            node(hasher, current, *sibling)
        } else {
            node(hasher, *sibling, current)
        };
        used += 1;
        width = width.div_ceil(2);
        position /= 2;
    }
    used == proof.siblings.len() && finish(hasher, domain, current, proof.leaf_count) == root
}

fn leaf(hasher: &dyn Hasher, bytes: &[u8]) -> Hash32 {
    hasher.hash(DOMAIN_LEAF, &[bytes])
}

fn node(hasher: &dyn Hasher, left: Hash32, right: Hash32) -> Hash32 {
    hasher.hash(DOMAIN_NODE, &[&left.0, &right.0])
}

fn pad(hasher: &dyn Hasher) -> Hash32 {
    hasher.hash(DOMAIN_PAD, &[])
}

fn finish(hasher: &dyn Hasher, domain: &[u8], tree: Hash32, leaf_count: usize) -> Hash32 {
    hasher.hash(
        DOMAIN_ROOT,
        &[domain, &tree.0, &(leaf_count as u64).to_le_bytes()],
    )
}

#[cfg(test)]
mod tests {
    use super::{prove, root_of, sequence_chunks, verify};
    use crate::hash::TestHasher;
    use crate::to_vec;

    const DOMAIN: &[u8] = b"test-tree-v1";

    fn chunks(count: usize) -> Vec<Vec<u8>> {
        (0..count).map(|i| vec![u8::try_from(i).unwrap()]).collect()
    }

    #[test]
    fn every_leaf_proves_at_every_width() {
        let hasher = TestHasher;
        for count in 1..=9 {
            let leaves = chunks(count);
            let root = root_of(&hasher, DOMAIN, &leaves);
            for index in 0..count {
                let proof = prove(&hasher, &leaves, index).expect("index names a leaf");
                assert!(
                    verify(&hasher, DOMAIN, root, &leaves[index], &proof),
                    "leaf {index} of {count} failed to verify"
                );
            }
        }
    }

    #[test]
    fn a_proof_for_a_leaf_that_is_not_there_is_refused() {
        let hasher = TestHasher;
        assert!(prove(&hasher, &chunks(4), 4).is_none());
        assert!(prove(&hasher, &[], 0).is_none());
    }

    #[test]
    fn an_altered_leaf_fails() {
        let hasher = TestHasher;
        let leaves = chunks(5);
        let root = root_of(&hasher, DOMAIN, &leaves);
        let proof = prove(&hasher, &leaves, 2).unwrap();
        assert!(verify(&hasher, DOMAIN, root, &leaves[2], &proof));
        assert!(!verify(&hasher, DOMAIN, root, &[0xFF], &proof));
    }

    #[test]
    fn a_proof_moved_to_another_position_fails() {
        let hasher = TestHasher;
        let leaves = chunks(5);
        let root = root_of(&hasher, DOMAIN, &leaves);
        let mut proof = prove(&hasher, &leaves, 2).unwrap();
        proof.index = 3;
        assert!(!verify(&hasher, DOMAIN, root, &leaves[2], &proof));
    }

    #[test]
    fn a_proof_with_a_tampered_sibling_fails() {
        let hasher = TestHasher;
        let leaves = chunks(5);
        let root = root_of(&hasher, DOMAIN, &leaves);
        let mut proof = prove(&hasher, &leaves, 1).unwrap();
        proof.siblings[0].0[0] ^= 1;
        assert!(!verify(&hasher, DOMAIN, root, &leaves[1], &proof));
    }

    /// The height a proof walks comes from its leaf count, so padding it out
    /// or trimming it does not buy a shorter or longer tree.
    #[test]
    fn a_proof_of_the_wrong_height_fails() {
        let hasher = TestHasher;
        let leaves = chunks(5);
        let root = root_of(&hasher, DOMAIN, &leaves);

        let mut extra = prove(&hasher, &leaves, 1).unwrap();
        extra.siblings.push(super::pad(&hasher));
        assert!(!verify(&hasher, DOMAIN, root, &leaves[1], &extra));

        let mut missing = prove(&hasher, &leaves, 1).unwrap();
        missing.siblings.pop();
        assert!(!verify(&hasher, DOMAIN, root, &leaves[1], &missing));
    }

    /// A tree of one leaf must not be that leaf's own hash, or a leaf could
    /// be presented as a root.
    #[test]
    fn a_single_leaf_tree_is_not_its_leaf() {
        let hasher = TestHasher;
        assert_ne!(
            root_of(&hasher, DOMAIN, &chunks(1)),
            super::leaf(&hasher, &[0])
        );
    }

    /// Padding with a distinct domain rather than by duplication: a tree of
    /// three leaves must not collide with one of four whose last leaf is
    /// whatever the padding happened to be.
    #[test]
    fn leaf_counts_do_not_collide() {
        let hasher = TestHasher;
        let roots: Vec<_> = (0..=8)
            .map(|n| root_of(&hasher, DOMAIN, &chunks(n)))
            .collect();
        for (i, a) in roots.iter().enumerate() {
            for (j, b) in roots.iter().enumerate() {
                assert!(i == j || a != b, "{i} leaves and {j} leaves share a root");
            }
        }
    }

    #[test]
    fn a_sequence_chunks_into_its_elements() {
        let hasher = TestHasher;
        let values = [1u32, 2, 3];
        let leaves = sequence_chunks(&values).unwrap();
        assert_eq!(leaves.len(), 3);
        let proof = prove(&hasher, &leaves, 1).unwrap();
        let root = root_of(&hasher, DOMAIN, &leaves);
        assert!(verify(
            &hasher,
            DOMAIN,
            root,
            &to_vec(&2u32).unwrap(),
            &proof
        ));
    }

    /// The same leaves under two domains are two trees: a receipt list and a
    /// witness list of identical hashes must not agree, and a proof against
    /// one must not verify as the other.
    #[test]
    fn domains_separate_identical_leaves() {
        let hasher = TestHasher;
        let leaves = chunks(4);
        let ours = root_of(&hasher, DOMAIN, &leaves);
        let theirs = root_of(&hasher, b"other-tree-v1", &leaves);
        assert_ne!(ours, theirs);

        let proof = prove(&hasher, &leaves, 2).unwrap();
        assert!(verify(&hasher, DOMAIN, ours, &leaves[2], &proof));
        assert!(!verify(&hasher, b"other-tree-v1", ours, &leaves[2], &proof));
        assert!(!verify(&hasher, DOMAIN, theirs, &leaves[2], &proof));
    }

    /// Empty trees are domain-bound too, so "no receipts" and "no witnesses"
    /// are different claims.
    #[test]
    fn empty_trees_do_not_share_a_root_across_domains() {
        let hasher = TestHasher;
        assert_ne!(
            root_of(&hasher, DOMAIN, &[]),
            root_of(&hasher, b"other-tree-v1", &[])
        );
    }
}
