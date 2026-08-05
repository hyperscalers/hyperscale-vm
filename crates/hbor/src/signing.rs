//! Signing preimages.
//!
//! A signature must commit to a message, and "the message" is a byte string
//! someone has to choose. Choosing it by hand — a domain tag, then fields
//! concatenated in a remembered order, with lengths written wherever the
//! author noticed concatenation was ambiguous — is how the workspace does it
//! today, and it is a second encoding of types that already have one.
//!
//! Here the preimage *is* the canonical encoding, of the signed subset,
//! under a framed domain. That makes the property those hand-written
//! builders were arguing for a consequence rather than a claim: distinct
//! signed contents have distinct preimages because the encoding is
//! canonical, not because someone remembered to length-prefix the right
//! fields.
//!
//! # The domain is framed
//!
//! The domain is written with its length, not concatenated raw. Unframed, a
//! domain that is a prefix of another collides — `"...-v1"` followed by
//! content beginning `'0'` is `"...-v10"` followed by the rest. One domain
//! in existence hides this; the second one finds it.
//!
//! # There is no `signing_hash`
//!
//! Hashing the preimage is the caller's, with the caller's hash. A method
//! here that also applied the domain through a hasher's domain parameter
//! would make two byte strings for one commitment — the exact thing this
//! encoding exists to prevent. The domain is in the preimage; hash the
//! preimage.

use crate::EncodeError;

/// A type whose signature covers a subset of its fields.
///
/// Derived by `#[hbor(signing_domain = "...")]`, with the fields a signature
/// cannot cover — the signature itself, the key that verifies it — marked
/// `#[hbor(unsigned)]`. Those fields stay on the wire; they are absent only
/// from the preimage.
///
/// Adding a field to such a type puts it in the preimage unless it is
/// explicitly marked unsigned, so widening a message cannot silently leave
/// the new content unauthenticated.
pub trait HborSigned {
    /// What this type's signatures are for.
    ///
    /// Two types, or two versions of one type, must not share a domain: it
    /// is what stops a signature gathered for one message from verifying
    /// against another.
    const SIGNING_DOMAIN: &'static [u8];

    /// The byte string a signature over this value covers: the framed
    /// domain, then the canonical encoding of every signed field in
    /// declaration order.
    ///
    /// The preimage is encoded at the default nesting cap, whatever cap the
    /// consumer's decoder uses. That is not a compatibility surface: depth
    /// charges write no bytes, so any two parties that can produce a
    /// value's preimage produce the same bytes — the cap decides only
    /// whether a value nested past it has a preimage at all.
    ///
    /// # Errors
    ///
    /// [`EncodeError`], as encoding the signed fields.
    fn signing_bytes(&self) -> Result<Vec<u8>, EncodeError>;
}
