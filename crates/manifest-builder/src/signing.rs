//! Wrapping a composed tree in an envelope, and signing it.
//!
//! The last step a client takes, and the first one that needs a secret.
//! Everything below this builds a graph; this puts fee terms, a validity
//! window and a network word around one and hands it to a key.
//!
//! Neither the hash nor the curve is here. What a signature covers is the
//! envelope's own digest, which the vocabulary defines; the hash reaching
//! it arrives through [`Hasher`] and the signature through
//! [`AccountSigner`], which is what lets a wallet sign without this crate
//! knowing what blake3 or ed25519 are.

use hyperscale_hbor::EncodeError;
use hyperscale_vm_effects::{EnvelopeTree, Hasher, encode_tree};
use hyperscale_vm_types::{
    AccountSigner, NetworkId, PrincipalAddr, SchemeId, SubintentSig, TransactionBody,
    TransactionEnvelope,
};

/// What a signer commits to beyond the manifest.
///
/// Terms that always travel together: they are the envelope's rather than
/// the graph's, and a caller choosing one chooses all of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The most the signer will pay to have this transaction carried.
    pub max_fee: u128,
    /// The signed execution ceiling, in fuel.
    pub gas_limit: u64,
    /// When the transaction may be included: the inclusive start of the
    /// window, in weighted-time milliseconds.
    pub validity_start_ms: u64,
    /// The window's exclusive end.
    pub validity_end_ms: u64,
    /// Content riding the signature and nothing else.
    ///
    /// A transaction's hash covers the whole signed envelope, so two
    /// otherwise identical submissions inside one validity window are one
    /// transaction and the second deduplicates away. Varying this is how a
    /// caller keeps them distinct.
    pub message: Vec<u8>,
}

/// An unsigned envelope around `tree`, naming `payer` and `network`.
///
/// The scheme is [`SchemeId::NONE`] and the material is empty: an envelope
/// names no scheme until somebody signs it, and nothing verifies under
/// none.
#[must_use]
pub fn wrap(
    tree: &EnvelopeTree,
    subintent_sigs: Vec<SubintentSig>,
    payer: PrincipalAddr,
    network: NetworkId,
    terms: Terms,
) -> TransactionEnvelope {
    TransactionEnvelope {
        body: TransactionBody::Call(encode_tree(tree)),
        subintent_sigs,
        fee_payer: payer,
        max_fee: terms.max_fee,
        gas_limit: terms.gas_limit,
        validity_start_ms: terms.validity_start_ms,
        validity_end_ms: terms.validity_end_ms,
        message: terms.message,
        network,
        signer_scheme: SchemeId::NONE,
        signer: Vec::new(),
        signature: Vec::new(),
    }
}

/// An unsigned envelope publishing `artifact`, naming `payer` and
/// `network`.
///
/// The `Publish` twin of [`wrap`]: same terms, same signing path, and a
/// body that carries the artifact's bytes instead of a call tree. A
/// host with keys signs it with [`sign`], exactly as it signs a call.
#[must_use]
pub fn wrap_publish(
    artifact: Vec<u8>,
    payer: PrincipalAddr,
    network: NetworkId,
    terms: Terms,
) -> TransactionEnvelope {
    TransactionEnvelope {
        body: TransactionBody::Publish(artifact),
        subintent_sigs: Vec::new(),
        fee_payer: payer,
        max_fee: terms.max_fee,
        gas_limit: terms.gas_limit,
        validity_start_ms: terms.validity_start_ms,
        validity_end_ms: terms.validity_end_ms,
        message: terms.message,
        network,
        signer_scheme: SchemeId::NONE,
        signer: Vec::new(),
        signature: Vec::new(),
    }
}

/// Sign an envelope's content, filling its scheme, key and signature.
///
/// The scheme is stamped before the preimage is taken, because a scheme
/// is signed content: a signer commits to which one they used, and an
/// envelope re-tagged afterwards loses the signature that covered it.
///
/// # Errors
///
/// [`EncodeError`] when the envelope's content does not encode — a
/// locally built body past the wire cap, which a decoded one never is.
/// A signer is handed the refusal rather than a signature over bytes no
/// envelope can carry.
pub fn sign<S: AccountSigner>(
    mut envelope: TransactionEnvelope,
    key: &S,
    hasher: &dyn Hasher,
) -> Result<TransactionEnvelope, EncodeError> {
    envelope.signer_scheme = key.scheme();
    let digest = envelope.signing_digest(hasher)?;
    envelope.signer = key.public_key_bytes();
    envelope.signature = key.sign_digest(&digest);
    Ok(envelope)
}

/// One bound subintent's signature over its declaration hash.
///
/// The scheme is stamped beside the material it describes, so a signer's
/// key and their claim about which curve produced it are written in one
/// place and cannot drift apart.
#[must_use]
pub fn sign_subintent<S: AccountSigner>(key: &S, declaration_hash: &[u8; 32]) -> SubintentSig {
    SubintentSig {
        scheme: key.scheme(),
        public_key: key.public_key_bytes(),
        signature: key.sign_digest(declaration_hash),
    }
}
