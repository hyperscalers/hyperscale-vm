//! Wrapping a composed tree in an envelope, and signing it.
//!
//! The last step a client takes, and the first one that needs a secret.
//! Everything below this builds a tree; this puts the terms beside it
//! and hands the envelope to a key.
//!
//! Neither the hash nor the curve is here. What a signature covers is the
//! envelope's own digest, which the vocabulary defines; the hash reaching
//! it arrives through [`Hasher`] and the signature through
//! [`AccountSigner`], which is what lets a wallet sign without this crate
//! knowing what blake3 or ed25519 are.

use hyperscale_hbor::EncodeError;
use hyperscale_vm_effects::{
    EnvelopeTree, Hasher, Intent, IntentHeader, ManifestGraph, encode_tree,
};
pub use hyperscale_vm_types::Terms;
use hyperscale_vm_types::{
    AccountSigner, PrincipalAddr, SchemeId, SubintentSig, TransactionEnvelope,
};

/// An unsigned envelope around `tree`, stating `terms`.
///
/// The window and the network are each intent's own header, stated
/// when it was opened. The scheme is [`SchemeId::NONE`] and the
/// material is empty: an envelope names no scheme until somebody signs
/// it, and nothing verifies under none.
#[must_use]
pub fn wrap(
    tree: &EnvelopeTree,
    subintent_sigs: Vec<SubintentSig>,
    terms: Terms,
) -> TransactionEnvelope {
    TransactionEnvelope {
        tree: encode_tree(tree),
        terms,
        artifact: None,
        subintent_sigs,
        signer_scheme: SchemeId::NONE,
        signer: Vec::new(),
        signature: Vec::new(),
    }
}

/// An unsigned envelope publishing `artifact`: a root acting as
/// `publisher` under `header` that calls nothing, stating `terms`, and
/// the artifact beside it.
///
/// The `Publish` twin of [`wrap`]: same terms, same signing path, and
/// an artifact where a call has a graph. A host with keys signs it with
/// [`sign`], exactly as it signs a call.
#[must_use]
pub fn wrap_publish(
    artifact: Vec<u8>,
    publisher: PrincipalAddr,
    header: IntentHeader,
    terms: Terms,
) -> TransactionEnvelope {
    let root = Intent::leaf(header, publisher, ManifestGraph::default());
    TransactionEnvelope {
        tree: encode_tree(&EnvelopeTree::of_one(root)),
        terms,
        artifact: Some(artifact),
        subintent_sigs: Vec::new(),
        signer_scheme: SchemeId::NONE,
        signer: Vec::new(),
        signature: Vec::new(),
    }
}

/// Sign an envelope's content, filling its scheme, key and signature.
///
/// The scheme and the key are stamped before the preimage is taken,
/// because both are signed content: a signer commits to which key they
/// used and under which scheme, and an envelope re-keyed or re-tagged
/// afterwards loses the signature that covered it.
///
/// # Errors
///
/// [`EncodeError`] when the envelope's content does not encode — a
/// locally built artifact past the wire cap, which a decoded one never
/// is. A signer is handed the refusal rather than a signature over bytes
/// no envelope can carry.
pub fn sign<S: AccountSigner>(
    mut envelope: TransactionEnvelope,
    key: &S,
    hasher: &dyn Hasher,
) -> Result<TransactionEnvelope, EncodeError> {
    envelope.signer_scheme = key.scheme();
    envelope.signer = key.public_key_bytes();
    let digest = envelope.signing_digest(hasher)?;
    envelope.signature = key.sign_digest(&digest);
    Ok(envelope)
}

/// One member's signature over its intent hash.
///
/// The scheme is stamped beside the material it describes, so a signer's
/// key and their claim about which curve produced it are written in one
/// place and cannot drift apart.
#[must_use]
pub fn sign_subintent<S: AccountSigner>(key: &S, intent_hash: &[u8; 32]) -> SubintentSig {
    SubintentSig {
        scheme: key.scheme(),
        public_key: key.public_key_bytes(),
        signature: key.sign_digest(intent_hash),
    }
}
