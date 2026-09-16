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
pub use hyperscale_vm_effects::attest;
use hyperscale_vm_effects::{Hasher, Intent, IntentHeader, IntentTree, ManifestGraph, encode_tree};
pub use hyperscale_vm_types::Terms;
use hyperscale_vm_types::{AccountSigner, PrincipalAddr, TransactionEnvelope};

/// An unsigned envelope around `tree`, stating `terms`.
///
/// The window and the network are each intent's own header, stated
/// when it was opened. Every member carries its own attestations inside
/// the tree; the root's are given by [`sign`], one key at a time.
#[must_use]
pub fn wrap(tree: &IntentTree, terms: Terms) -> TransactionEnvelope {
    TransactionEnvelope {
        tree: encode_tree(tree),
        terms,
        artifact: None,
        signatures: Vec::new(),
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
        tree: encode_tree(&IntentTree::of_one(root)),
        terms,
        artifact: Some(artifact),
        signatures: Vec::new(),
    }
}

/// Attest an envelope's content with `key`, standing the attestation
/// beside those already given.
///
/// The caller signs in the order the root intent declares its attesting
/// principals: an attestation pairs by position with the principal
/// there, and one whose key derives another principal is refused.
///
/// # Errors
///
/// [`EncodeError`] when the envelope's content does not encode — a
/// locally built artifact past the wire cap, which a decoded one never
/// is. A signer is handed the refusal rather than a signature over bytes
/// no envelope can carry.
pub fn sign<S: AccountSigner + ?Sized>(
    mut envelope: TransactionEnvelope,
    key: &S,
    hasher: &dyn Hasher,
) -> Result<TransactionEnvelope, EncodeError> {
    let digest = envelope.signing_digest(hasher)?;
    envelope.signatures.push(attest(key, &digest));
    Ok(envelope)
}
