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

use hyperscale_hbor::{Bytes, Capped, EncodeError, Overflow};
pub use hyperscale_vm_effects::attest;
use hyperscale_vm_effects::{Hasher, Intent, IntentHeader, IntentTree, ManifestGraph, encode_tree};
pub use hyperscale_vm_types::Terms;
use hyperscale_vm_types::{AccountSigner, MAX_ARTIFACT_BYTES, PrincipalAddr, TransactionEnvelope};

/// Why an envelope could not be signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The envelope's content does not encode.
    #[error("the envelope does not encode: {0}")]
    Encode(#[from] EncodeError),
    /// The envelope already carries every attestation it may.
    #[error("attestations: {0}")]
    Attestations(#[from] Overflow),
}

/// An unsigned envelope around `tree`, stating `terms`.
///
/// The window and the network are each intent's own header, stated
/// when it was opened. Every member carries its own attestations inside
/// the tree; the root's are given by [`sign`], one key at a time.
///
/// # Errors
///
/// [`Overflow`] for a tree that encodes past the envelope's cap — a
/// locally built one, since a decoded tree never is.
pub fn wrap(tree: &IntentTree, terms: Terms) -> Result<TransactionEnvelope, Overflow> {
    Ok(TransactionEnvelope {
        tree: Bytes::new(encode_tree(tree))?,
        terms,
        artifact: None,
        signatures: Capped::empty(),
    })
}

/// An unsigned envelope publishing `artifact`: a root acting as
/// `publisher` under `header` that calls nothing, stating `terms`, and
/// the artifact beside it.
///
/// The `Publish` twin of [`wrap`]: same terms, same signing path, and
/// an artifact where a call has a graph. A host with keys signs it with
/// [`sign`], exactly as it signs a call.
///
/// # Panics
///
/// Never in practice: the tree is one leaf with no graph, of a fixed
/// size far under the envelope's cap.
#[must_use]
pub fn wrap_publish(
    artifact: Bytes<MAX_ARTIFACT_BYTES>,
    publisher: PrincipalAddr,
    header: IntentHeader,
    terms: Terms,
) -> TransactionEnvelope {
    let root = Intent::leaf(header, publisher, ManifestGraph::default());
    TransactionEnvelope {
        // One leaf with no graph: a tree of fixed size, far under the cap.
        tree: Bytes::new(encode_tree(&IntentTree::of_one(root)))
            .expect("a publish root with no graph fits the tree cap"),
        terms,
        artifact: Some(artifact),
        signatures: Capped::empty(),
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
/// [`SignError`] when the envelope's content does not encode, or when it
/// already carries every attestation it may. A signer is handed the
/// refusal rather than a signature over bytes no envelope can carry.
pub fn sign<S: AccountSigner + ?Sized>(
    mut envelope: TransactionEnvelope,
    key: &S,
    hasher: &dyn Hasher,
) -> Result<TransactionEnvelope, SignError> {
    let digest = envelope.signing_digest(hasher)?;
    envelope.signatures.push(attest(key, &digest))?;
    Ok(envelope)
}
