//! The protocol hash behind the VM's hashing seam.
//!
//! Blake3 over the length-framed domain and parts: pure, and framed so
//! that moving bytes across a part boundary always changes the digest.
//!
//! It sits with the wire types rather than with the effects binding
//! because both need it — an envelope's signing digest is taken here, and
//! the effect vocabulary derives every address and child key through the
//! same seam. Two definitions would be two identities for one value, and
//! the two would drift exactly once, so the embedder re-exports this one
//! rather than keeping its own.
//!
//! The seam itself stays a parameter: everything here takes
//! [`Hasher`], and this is the
//! implementation a network runs rather than the only one it can.

use blake3::Hasher as Blake3;
use hyperscale_hbor::hash::{Hash32, Hasher};

/// The protocol hash: blake3 over the length-framed domain and parts.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProtocolHasher;

impl Hasher for ProtocolHasher {
    fn hash(&self, domain: &[u8], parts: &[&[u8]]) -> Hash32 {
        let mut hasher = Blake3::new();
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        Hash32(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::hash::Hasher;

    use super::ProtocolHasher;

    /// The framing is what the digest is over, so moving a byte across a
    /// boundary moves the answer.
    ///
    /// Two part lists with the same concatenation are the case that would
    /// collide without the lengths, and the domain is framed on the same
    /// terms — a hash of one meaning must not be reachable by writing
    /// another.
    #[test]
    fn moving_a_byte_across_a_boundary_moves_the_digest() {
        let hasher = ProtocolHasher;
        assert_ne!(
            hasher.hash(b"d", &[b"ab", b"c"]),
            hasher.hash(b"d", &[b"a", b"bc"])
        );
        assert_ne!(hasher.hash(b"d", &[b"abc"]), hasher.hash(b"da", &[b"bc"]));
        // And it is pure.
        assert_eq!(hasher.hash(b"d", &[b"abc"]), hasher.hash(b"d", &[b"abc"]));
    }
}
