//! The signature schemes user-layer auth material belongs to.
//!
//! A scheme is three facts and an arithmetic: how wide its keys are, how
//! wide its signatures are, what verifying one costs, and the computation
//! that answers whether a signature is good. The first three are properties
//! of the scheme rather than of a deployment, so they live with the wire
//! vocabulary that has to size and price the material — a signature's
//! verification cost cannot be charged by a crate that cannot see which
//! scheme produced it. The fourth is curve arithmetic, which this workspace
//! does not carry; [`SchemeVerifier`] is how an embedder supplies it.
//!
//! What the registry deliberately does not say is which schemes a network
//! accepts at a given height. Describing a scheme is a vocabulary question
//! and turning it on is a protocol-version question, and keeping the two
//! apart is what lets a scheme be sized, priced, and encoded ahead of any
//! chain accepting it.

use hyperscale_hbor::Hbor;

/// The signature scheme a principal's auth material belongs to.
///
/// A principal address commits to the scheme alongside the key, so one
/// public key presented under two schemes is two principals — a scheme
/// added later cannot land on an address already in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct SchemeId(pub u16);

impl SchemeId {
    /// No scheme: what an envelope names before it is signed, and what a
    /// zero-filled buffer decodes to. Registered to nothing, so material
    /// presented under it verifies under nothing.
    pub const NONE: Self = Self(0);

    /// Ed25519 over RFC 8032, keys as compressed Edwards points.
    pub const ED25519: Self = Self(1);

    /// ECDSA over secp256k1, keys as SEC1 compressed points and
    /// signatures as compact `r || s` under a low-`s` rule.
    ///
    /// A third scheme arrives with its verifier and takes the next value;
    /// nothing may claim one before then, because the address space would
    /// be spent on something no chain could verify.
    pub const SECP256K1: Self = Self(2);

    /// What this id is registered as, or `None` if nothing is.
    ///
    /// Zero is registered to nothing and never will be: it is what a
    /// zero-filled buffer decodes to, and a scheme sitting there would let
    /// absent material read as material under a live scheme.
    #[must_use]
    pub const fn spec(self) -> Option<SchemeSpec> {
        let mut index = 0;
        while index < REGISTRY.len() {
            let (id, spec) = REGISTRY[index];
            if id.0 == self.0 {
                return Some(spec);
            }
            index += 1;
        }
        None
    }
}

/// Every registered scheme, by id.
const REGISTRY: &[(SchemeId, SchemeSpec)] = &[
    (
        SchemeId::ED25519,
        SchemeSpec {
            key_len: 32,
            sig_len: 64,
            verify_weight: 1,
        },
    ),
    (
        SchemeId::SECP256K1,
        SchemeSpec {
            key_len: 33,
            sig_len: 64,
            verify_weight: 2,
        },
    ),
];

/// The widest public key any registered scheme has.
///
/// A wire bound on material whose scheme is not yet known — a decoder
/// reads the bytes before it can look the scheme up, and this is what
/// stops it allocating for a scheme nobody registered. The exact width
/// is [`SchemeSpec::admits`]'s to enforce once the scheme is in hand.
pub const MAX_KEY_BYTES: usize = widest(true);

/// The widest signature any registered scheme has, on the same terms as
/// [`MAX_KEY_BYTES`].
pub const MAX_SIG_BYTES: usize = widest(false);

const fn widest(keys: bool) -> usize {
    let mut widest = 0;
    let mut index = 0;
    while index < REGISTRY.len() {
        let (_, spec) = REGISTRY[index];
        let width = if keys { spec.key_len } else { spec.sig_len };
        if width > widest {
            widest = width;
        }
        index += 1;
    }
    widest
}

/// How wide a registered scheme's material is and what verifying it costs.
///
/// Both widths are exact, which is a condition on registration rather than
/// an observation about the schemes registered so far: a scheme whose
/// signatures vary in length has no entry of this shape, because a cost
/// declared before the bytes arrive is what the widths are read for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemeSpec {
    /// Width of a public key, in bytes.
    pub key_len: usize,
    /// Width of a signature, in bytes.
    pub sig_len: usize,
    /// Cost of one verification, in ed25519 verifications.
    ///
    /// A ratio between schemes rather than a price: what one ed25519
    /// verification costs against fuel and footprint is a weight, and the
    /// weights are [`crate::work`]'s. Placeholder ratios, on the same
    /// terms as those weights — measured against real implementations
    /// rather than chosen here, and a scheme whose verifier is slower
    /// than its entry claims is underpriced rather than unsound.
    pub verify_weight: u64,
}

impl SchemeSpec {
    /// Whether `key` is the width this scheme gives a public key.
    ///
    /// Wire caps bound what a decoder will allocate; this is the exact
    /// answer, and material failing it is material no scheme claims —
    /// never a short key padded out or a long one truncated.
    #[must_use]
    pub const fn admits_key(&self, key: &[u8]) -> bool {
        key.len() == self.key_len
    }

    /// Whether `key` and `signature` are both widths this scheme gives.
    #[must_use]
    pub const fn admits(&self, key: &[u8], signature: &[u8]) -> bool {
        self.admits_key(key) && signature.len() == self.sig_len
    }
}

/// Signature verification for the schemes the registry describes.
///
/// Implementations must be pure — equal `(scheme, key, signature, message)`
/// yields the same answer on every call and every node. A verdict that
/// varied with the verifier would split the chain that carried the
/// envelope, which is the one failure this seam exists to make impossible
/// to introduce quietly.
///
/// The answer is a bit and nothing more. An unregistered scheme, material
/// of a width the registry does not give it, a key that decodes to no point,
/// and a well-formed signature over a different message are all the same
/// `false`: no caller may act on the difference, so reporting it apart only
/// invites one to try.
pub trait SchemeVerifier {
    /// Whether `signature` is `key`'s signature over `message` under
    /// `scheme`.
    fn verify(&self, scheme: SchemeId, key: &[u8], signature: &[u8], message: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::{MAX_KEY_BYTES, MAX_SIG_BYTES, REGISTRY, SchemeId, SchemeSpec};

    #[test]
    fn the_launch_schemes_are_registered_at_their_wire_widths() {
        assert_eq!(
            SchemeId::ED25519.spec(),
            Some(SchemeSpec {
                key_len: 32,
                sig_len: 64,
                verify_weight: 1,
            })
        );
        assert_eq!(
            SchemeId::SECP256K1.spec(),
            Some(SchemeSpec {
                key_len: 33,
                sig_len: 64,
                verify_weight: 2,
            })
        );
    }

    /// Two schemes sharing a signature width is ordinary; two sharing an
    /// id is the registry contradicting itself.
    #[test]
    fn every_id_is_registered_once() {
        for (index, (id, _)) in REGISTRY.iter().enumerate() {
            assert!(
                !REGISTRY[..index].iter().any(|(seen, _)| seen == id),
                "{id:?} is registered twice"
            );
        }
    }

    /// The caps are read off the registry, so a scheme cannot register
    /// material the wire refuses to carry.
    #[test]
    fn the_caps_cover_every_registered_scheme() {
        for (id, spec) in REGISTRY {
            assert_eq!(id.spec(), Some(*spec));
            assert!(spec.key_len <= MAX_KEY_BYTES);
            assert!(spec.sig_len <= MAX_SIG_BYTES);
        }
        assert!(
            REGISTRY
                .iter()
                .any(|(_, spec)| spec.key_len == MAX_KEY_BYTES)
        );
        assert!(
            REGISTRY
                .iter()
                .any(|(_, spec)| spec.sig_len == MAX_SIG_BYTES)
        );
    }

    #[test]
    fn a_scheme_admits_only_its_own_widths() {
        let spec = SchemeId::ED25519.spec().expect("ed25519 is registered");
        assert!(spec.admits(&[0; 32], &[0; 64]));
        assert!(!spec.admits(&[0; 31], &[0; 64]));
        assert!(!spec.admits(&[0; 33], &[0; 64]));
        assert!(!spec.admits(&[0; 32], &[0; 63]));
        assert!(!spec.admits(&[], &[]));
    }

    /// Zero is what absent material decodes to, so a scheme there would
    /// make an empty envelope readable as one signed under a live scheme.
    #[test]
    fn zero_is_registered_to_nothing() {
        assert_eq!(SchemeId(0).spec(), None);
    }

    #[test]
    fn an_unclaimed_id_has_no_entry() {
        assert_eq!(SchemeId(3).spec(), None);
        assert_eq!(SchemeId(u16::MAX).spec(), None);
    }
}
