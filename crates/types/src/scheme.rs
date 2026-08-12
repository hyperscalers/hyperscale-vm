//! The signature schemes user-layer auth material belongs to.
//!
//! A scheme is three facts and an arithmetic: how wide its keys are, how
//! wide its signatures are, what verifying one costs, and the computation
//! that answers whether a signature is good. The first three are properties
//! of the scheme rather than of a deployment, so they live with the wire
//! vocabulary that has to size and price the material — a signature's
//! verification cost cannot be charged by a crate that cannot see which
//! scheme produced it. The fourth is curve arithmetic, which this workspace
//! does not carry; [`Verifier`] is how an embedder supplies it.
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
    /// Ed25519, the only scheme the protocol verifies. A second scheme
    /// arrives with its verifier and takes the next value; nothing may
    /// claim one before then, because the address space would be spent.
    pub const ED25519: Self = Self(1);

    /// What this id is registered as, or `None` if nothing is.
    ///
    /// Zero is registered to nothing and never will be: it is what a
    /// zero-filled buffer decodes to, and a scheme sitting there would let
    /// absent material read as material under a live scheme.
    #[must_use]
    pub const fn spec(self) -> Option<SchemeSpec> {
        match self {
            Self::ED25519 => Some(SchemeSpec {
                key_len: 32,
                sig_len: 64,
                verify_weight: 1,
            }),
            _ => None,
        }
    }
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
    /// weights are [`crate::work`]'s.
    pub verify_weight: u64,
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
pub trait Verifier {
    /// Whether `signature` is `key`'s signature over `message` under
    /// `scheme`.
    fn verify(&self, scheme: SchemeId, key: &[u8], signature: &[u8], message: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::{SchemeId, SchemeSpec};

    #[test]
    fn ed25519_is_registered_at_its_wire_widths() {
        assert_eq!(
            SchemeId::ED25519.spec(),
            Some(SchemeSpec {
                key_len: 32,
                sig_len: 64,
                verify_weight: 1,
            })
        );
    }

    /// Zero is what absent material decodes to, so a scheme there would
    /// make an empty envelope readable as one signed under a live scheme.
    #[test]
    fn zero_is_registered_to_nothing() {
        assert_eq!(SchemeId(0).spec(), None);
    }

    #[test]
    fn an_unclaimed_id_has_no_entry() {
        assert_eq!(SchemeId(2).spec(), None);
        assert_eq!(SchemeId(u16::MAX).spec(), None);
    }
}
