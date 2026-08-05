//! Merkleization: a value's identity as a tree over its own fields.
//!
//! A hash over a whole encoding proves the whole value or nothing. A tree
//! over the fields proves one field to someone holding only the root — which
//! is what receipt trees, settled-wave roots, and witness roots are all
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
/// Derived by `#[derive(HborMerkle)]`. A type that derives it has its root as
/// its identity: hashing its encoding separately would be a second hash for
/// one value, which is the thing this encoding exists to avoid.
pub trait Chunked {
    /// This value's leaves, in declaration order, each the canonical
    /// encoding of one field or element.
    ///
    /// # Errors
    ///
    /// [`EncodeError`], as encoding the fields.
    fn chunks(&self) -> Result<Vec<Vec<u8>>, EncodeError>;

    /// This value's merkle root.
    ///
    /// # Errors
    ///
    /// [`EncodeError`], as [`Chunked::chunks`].
    fn merkle_root(&self, hasher: &dyn Hasher) -> Result<Hash32, EncodeError> {
        Ok(root_of(hasher, &self.chunks()?))
    }

    /// A proof that the leaf at `index` sits under this value's root.
    ///
    /// Returns `None` when `index` names no leaf.
    ///
    /// # Errors
    ///
    /// [`EncodeError`], as [`Chunked::chunks`].
    fn prove(&self, hasher: &dyn Hasher, index: usize) -> Result<Option<Proof>, EncodeError> {
        Ok(prove(hasher, &self.chunks()?, index))
    }
}

/// A sequence's leaves are its elements.
impl<T: HborEncode> Chunked for Vec<T> {
    fn chunks(&self) -> Result<Vec<Vec<u8>>, EncodeError> {
        self.iter().map(|element| to_vec(element)).collect()
    }
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

/// The root over `chunks`.
#[must_use]
pub fn root_of(hasher: &dyn Hasher, chunks: &[Vec<u8>]) -> Hash32 {
    let mut level: Vec<Hash32> = chunks.iter().map(|chunk| leaf(hasher, chunk)).collect();
    if level.is_empty() {
        return finish(hasher, pad(hasher), 0);
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(pad(hasher));
        }
        level = level
            .chunks_exact(2)
            .map(|pair| node(hasher, pair[0], pair[1]))
            .collect();
    }
    finish(hasher, level[0], chunks.len())
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
            .chunks_exact(2)
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
/// different height.
#[must_use]
pub fn verify(hasher: &dyn Hasher, root: Hash32, leaf_bytes: &[u8], proof: &Proof) -> bool {
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
    used == proof.siblings.len() && finish(hasher, current, proof.leaf_count) == root
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

fn finish(hasher: &dyn Hasher, tree: Hash32, leaf_count: usize) -> Hash32 {
    hasher.hash(DOMAIN_ROOT, &[&tree.0, &(leaf_count as u64).to_le_bytes()])
}

#[cfg(test)]
mod tests {
    use super::{Chunked, prove, root_of, verify};
    use crate::hash::TestHasher;
    use crate::to_vec;

    fn chunks(count: usize) -> Vec<Vec<u8>> {
        (0..count).map(|i| vec![u8::try_from(i).unwrap()]).collect()
    }

    #[test]
    fn every_leaf_proves_at_every_width() {
        let hasher = TestHasher;
        for count in 1..=9 {
            let leaves = chunks(count);
            let root = root_of(&hasher, &leaves);
            for index in 0..count {
                let proof = prove(&hasher, &leaves, index).expect("index names a leaf");
                assert!(
                    verify(&hasher, root, &leaves[index], &proof),
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
        let root = root_of(&hasher, &leaves);
        let proof = prove(&hasher, &leaves, 2).unwrap();
        assert!(verify(&hasher, root, &leaves[2], &proof));
        assert!(!verify(&hasher, root, &[0xFF], &proof));
    }

    #[test]
    fn a_proof_moved_to_another_position_fails() {
        let hasher = TestHasher;
        let leaves = chunks(5);
        let root = root_of(&hasher, &leaves);
        let mut proof = prove(&hasher, &leaves, 2).unwrap();
        proof.index = 3;
        assert!(!verify(&hasher, root, &leaves[2], &proof));
    }

    #[test]
    fn a_proof_with_a_tampered_sibling_fails() {
        let hasher = TestHasher;
        let leaves = chunks(5);
        let root = root_of(&hasher, &leaves);
        let mut proof = prove(&hasher, &leaves, 1).unwrap();
        proof.siblings[0].0[0] ^= 1;
        assert!(!verify(&hasher, root, &leaves[1], &proof));
    }

    /// The height a proof walks comes from its leaf count, so padding it out
    /// or trimming it does not buy a shorter or longer tree.
    #[test]
    fn a_proof_of_the_wrong_height_fails() {
        let hasher = TestHasher;
        let leaves = chunks(5);
        let root = root_of(&hasher, &leaves);

        let mut extra = prove(&hasher, &leaves, 1).unwrap();
        extra.siblings.push(super::pad(&hasher));
        assert!(!verify(&hasher, root, &leaves[1], &extra));

        let mut missing = prove(&hasher, &leaves, 1).unwrap();
        missing.siblings.pop();
        assert!(!verify(&hasher, root, &leaves[1], &missing));
    }

    /// A tree of one leaf must not be that leaf's own hash, or a leaf could
    /// be presented as a root.
    #[test]
    fn a_single_leaf_tree_is_not_its_leaf() {
        let hasher = TestHasher;
        assert_ne!(root_of(&hasher, &chunks(1)), super::leaf(&hasher, &[0]));
    }

    /// Padding with a distinct domain rather than by duplication: a tree of
    /// three leaves must not collide with one of four whose last leaf is
    /// whatever the padding happened to be.
    #[test]
    fn leaf_counts_do_not_collide() {
        let hasher = TestHasher;
        let roots: Vec<_> = (0..=8).map(|n| root_of(&hasher, &chunks(n))).collect();
        for (i, a) in roots.iter().enumerate() {
            for (j, b) in roots.iter().enumerate() {
                assert!(i == j || a != b, "{i} leaves and {j} leaves share a root");
            }
        }
    }

    #[test]
    fn a_sequence_chunks_into_its_elements() {
        let hasher = TestHasher;
        let values = vec![1u32, 2, 3];
        assert_eq!(values.chunks().unwrap().len(), 3);
        let proof = values.prove(&hasher, 1).unwrap().unwrap();
        let root = values.merkle_root(&hasher).unwrap();
        assert!(verify(&hasher, root, &to_vec(&2u32).unwrap(), &proof));
    }
}
