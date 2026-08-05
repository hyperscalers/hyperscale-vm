//! The hashing seam.
//!
//! Merkleization needs a hash; this crate must not name one. Every
//! derivation flows through one trait so the protocol hash is supplied at
//! integration and can move — the post-quantum track may well move it —
//! without touching anything here.
//!
//! Implementations must be pure, and must frame each part, so that moving
//! bytes between adjacent parts changes the output.

use core::fmt;

/// A 32-byte hash value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32(pub [u8; 32]);

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// Domain-separated hashing over framed parts.
///
/// Implementations must be pure — equal `(domain, parts)` inputs yield equal
/// output on every call and every node — and must frame each part, so moving
/// bytes between adjacent parts changes the output.
pub trait Hasher {
    /// Hash `parts` under `domain`.
    fn hash(&self, domain: &[u8], parts: &[&[u8]]) -> Hash32;
}

/// Test-grade hasher: four independently seeded, length-framed FNV-1a lanes
/// with a final bit mix. Deterministic and well spread, **not** collision
/// resistant — for fixtures and tests only.
#[derive(Clone, Copy, Debug, Default)]
pub struct TestHasher;

impl Hasher for TestHasher {
    fn hash(&self, domain: &[u8], parts: &[&[u8]]) -> Hash32 {
        let mut out = [0u8; 32];
        for (lane, chunk) in out.chunks_exact_mut(8).enumerate() {
            let mut state =
                0xcbf2_9ce4_8422_2325_u64 ^ (lane as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            feed(&mut state, domain);
            for part in parts {
                feed(&mut state, part);
            }
            chunk.copy_from_slice(&mix(state).to_le_bytes());
        }
        Hash32(out)
    }
}

fn feed(state: &mut u64, bytes: &[u8]) {
    for byte in (bytes.len() as u64)
        .to_le_bytes()
        .into_iter()
        .chain(bytes.iter().copied())
    {
        *state ^= u64::from(byte);
        *state = state.wrapping_mul(0x100_0000_01b3);
    }
}

const fn mix(mut z: u64) -> u64 {
    z ^= z >> 30;
    z = z.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::{Hasher, TestHasher};

    #[test]
    fn deterministic_and_framed() {
        let a = TestHasher.hash(b"d", &[b"ab", b"c"]);
        assert_eq!(a, TestHasher.hash(b"d", &[b"ab", b"c"]));
        // Part boundaries are semantic.
        assert_ne!(a, TestHasher.hash(b"d", &[b"a", b"bc"]));
        assert_ne!(a, TestHasher.hash(b"d", &[b"abc"]));
        // Domains separate.
        assert_ne!(a, TestHasher.hash(b"e", &[b"ab", b"c"]));
    }
}
