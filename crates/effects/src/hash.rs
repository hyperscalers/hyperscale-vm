//! The hashing seam, re-exported from the encoding crate.
//!
//! One `Hash32` and one `Hasher` span the codec, merkleization, and every
//! derivation here. A second definition would be a second identity for the
//! same value, and the two would drift exactly once.

pub use hyperscale_hbor::hash::{Hash32, Hasher, TestHasher};
