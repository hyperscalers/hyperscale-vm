//! The signed transaction envelope.
//!
//! The envelope carries the bound tree — the composer's root graph plus
//! every signed subintent — as canonical bytes, beside the signing-time
//! choices no node can derive: the fee payer, the fee ceiling and gas
//! limit, the validity window, a capped optional message, and the
//! network the composer means it for. The composer signs the whole
//! envelope, so distinct submissions differ in signed content.
//!
//! The tree stays opaque here: its vocabulary and codec live with the
//! effect machinery, and treating it as signed bytes is what keeps this
//! crate a leaf. Producing and verifying the signature binds a hash and a
//! curve, which belongs to the workspace that owns the protocol's
//! cryptography — what this type defines is the signed *content*, through
//! its derived preimage.

use core::fmt;

use hyperscale_hbor::{Hash32, Hbor};

use crate::address::Address;

/// The cap on an envelope body's bytes — a call tree or a package
/// artifact.
pub const MAX_TX_BYTES_LEN: usize = 1024 * 1024;

/// The cap on an envelope's optional message, in bytes.
pub const MAX_MESSAGE_LEN: usize = 1024;

/// The bound on subintents one envelope may compose, and so on the
/// signatures it carries for them.
pub const MAX_SUBINTENTS: usize = 32;

/// The abort class floor as a fraction of the signed fee ceiling:
/// aborting costs the payer a tenth of what it authorised. Placeholder
/// pricing — the number is calibrated against measured baselines, the
/// shape is that an abort is bounded strictly below the ceiling a
/// success may burn.
const ABORT_FLOOR_DIVISOR: u128 = 10;

/// A transaction's identity: the hash of its envelope's canonical bytes.
///
/// One value with two jobs that must never diverge: the kernel's canonical
/// ordering key for every commutative-mode decision, and the name every
/// consensus artifact — receipt, certificate, provision — attaches to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct TxHash(pub Hash32);

impl TxHash {
    /// The all-zero transaction hash: a placeholder, never an identity.
    pub const ZERO: Self = Self(Hash32([0u8; 32]));

    /// The raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0.0
    }

    /// Whether this is the all-zero placeholder.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.0.iter().all(|&byte| byte == 0)
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_string();
        write!(f, "TxHash({}..{})", &hex[..8], &hex[56..])
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The network an artifact is signed for — one byte, distinct per
/// network.
///
/// On the envelope it is a signed field, so a transaction composed for
/// one network never verifies under another's admission: the session
/// checks the named network before the signature, and renaming it
/// breaks the signature. Consensus signing reuses the same type as the
/// ambient context its preimages mix in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct NetworkId(pub u8);

/// One bound subintent's signature: the signer's key and their ed25519
/// signature over the subintent's declaration hash, in tree order.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct SubintentSig {
    /// The subintent signer's ed25519 public key; its derived account
    /// address must match the signer the tree binds.
    pub public_key: [u8; 32],
    /// The signature over the subintent's declaration hash.
    pub signature: [u8; 64],
}

/// What an envelope asks the chain for: a call graph to run, or a
/// package to publish.
///
/// Wholly one or the other. Every other field of the envelope — the fee
/// terms, the window, the message, the composer's signature — means the
/// same thing for both, which is why publishing rides this envelope
/// rather than a body of its own: fee assurance, engagement, and tick
/// settlement are the same machinery either way.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum TransactionBody {
    /// The bound envelope tree, canonically encoded; the effect
    /// vocabulary owns the encoding.
    Call(#[hbor(max = MAX_TX_BYTES_LEN)] Vec<u8>),
    /// A component artifact to publish under the composer's own prefix,
    /// its effect metadata section included. Content addressing covers
    /// the whole artifact, so the code and the signatures it declares
    /// cannot drift apart.
    Publish(#[hbor(max = MAX_TX_BYTES_LEN)] Vec<u8>),
}

/// A transaction: what it asks for and the signing-time choices, under
/// the composer's signature.
///
/// The signature covers the derived preimage — every field but the
/// composer's own key and signature, under the envelope domain — and the
/// hash of that preimage is also the identity fresh derivations root at:
/// distinct signed envelopes never mint the same fresh key.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-vm-envelope-v1")]
pub struct TransactionEnvelope {
    /// The call graph or the package.
    pub body: TransactionBody,
    /// One signature per bound subintent, in tree order.
    #[hbor(max = MAX_SUBINTENTS)]
    pub subintent_sigs: Vec<SubintentSig>,
    /// The fee-paying account — the composer's.
    pub fee_payer: Address,
    /// The signed fee ceiling, in fee units.
    pub max_fee: u128,
    /// The signed execution gas limit.
    pub gas_limit: u64,
    /// The signed validity window's inclusive start, in weighted-time
    /// milliseconds. The wire's range form must mirror the window.
    pub validity_start_ms: u64,
    /// The signed validity window's exclusive end.
    pub validity_end_ms: u64,
    /// An optional message, capped at [`MAX_MESSAGE_LEN`].
    #[hbor(max = MAX_MESSAGE_LEN)]
    pub message: Vec<u8>,
    /// The network this envelope is composed for. Signed like every
    /// other field, so the transaction can neither be replayed onto a
    /// network its composer never named nor re-targeted after signing.
    pub network: NetworkId,
    /// The composer's ed25519 public key.
    #[hbor(unsigned)]
    pub signer: [u8; 32],
    /// The composer's signature over the hash of
    /// [`signing_bytes`](hyperscale_hbor::HborSigned::signing_bytes).
    #[hbor(unsigned)]
    pub signature: [u8; 64],
}

impl TransactionEnvelope {
    /// The bound envelope tree, for a call.
    #[must_use]
    pub fn call_tree(&self) -> Option<&[u8]> {
        match &self.body {
            TransactionBody::Call(tree) => Some(tree),
            TransactionBody::Publish(_) => None,
        }
    }

    /// The component artifact, for a publish.
    #[must_use]
    pub fn artifact(&self) -> Option<&[u8]> {
        match &self.body {
            TransactionBody::Publish(artifact) => Some(artifact),
            TransactionBody::Call(_) => None,
        }
    }

    /// What an abort of this transaction burns from the payer's vault.
    ///
    /// Derived from signed content alone, so every payer-shard voter
    /// attests the same figure without reading any state.
    #[must_use]
    pub const fn abort_floor(&self) -> u128 {
        self.max_fee / ABORT_FLOOR_DIVISOR
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{HborSigned, assert_canonical, to_vec};

    use super::{Address, NetworkId, SubintentSig, TransactionBody, TransactionEnvelope};
    use crate::address::AddressClass;

    fn sample() -> TransactionEnvelope {
        TransactionEnvelope {
            body: TransactionBody::Call(vec![1, 2, 3]),
            subintent_sigs: vec![SubintentSig {
                public_key: [0x11; 32],
                signature: [0x22; 64],
            }],
            fee_payer: Address::new([0x33; 31], AddressClass::Principal),
            max_fee: 1_000_000,
            gas_limit: 500_000,
            validity_start_ms: 1_700_000_000_000,
            validity_end_ms: 1_700_000_060_000,
            message: b"hello".to_vec(),
            network: NetworkId(242),
            signer: [0x44; 32],
            signature: [0x55; 64],
        }
    }

    #[test]
    fn the_envelope_is_canonical() {
        assert_canonical(&sample());
    }

    /// The two fields a signature cannot cover ride the wire and are
    /// absent from the preimage; everything else is signed content.
    #[test]
    fn the_signature_covers_everything_but_itself() {
        let envelope = sample();
        let mut resigned = envelope.clone();
        resigned.signer = [0x99; 32];
        resigned.signature = [0xAA; 64];
        assert_eq!(
            envelope.signing_bytes().unwrap(),
            resigned.signing_bytes().unwrap()
        );
        assert_ne!(to_vec(&envelope).unwrap(), to_vec(&resigned).unwrap());

        let mut repriced = envelope;
        repriced.max_fee += 1;
        assert_ne!(
            repriced.signing_bytes().unwrap(),
            resigned.signing_bytes().unwrap()
        );
    }

    /// The named network is signed content: renaming it is a different
    /// preimage, so a re-targeted envelope cannot keep its signature.
    #[test]
    fn the_network_is_signed() {
        let signed = sample();
        let mut retargeted = sample();
        retargeted.network = NetworkId(1);
        assert_ne!(
            signed.signing_bytes().unwrap(),
            retargeted.signing_bytes().unwrap()
        );
    }

    /// The discriminant is signed content: the same bytes read as a call
    /// graph and as an artifact are different transactions.
    #[test]
    fn the_body_discriminant_is_signed() {
        let mut call = sample();
        call.body = TransactionBody::Call(vec![9]);
        let mut publish = sample();
        publish.body = TransactionBody::Publish(vec![9]);
        assert_ne!(
            call.signing_bytes().unwrap(),
            publish.signing_bytes().unwrap()
        );
    }
}
