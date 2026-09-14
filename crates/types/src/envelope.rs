//! The signed transaction envelope.
//!
//! The envelope carries the bound tree — the composer's root graph plus
//! every signed subintent — as canonical bytes, beside the signing-time
//! choices no node can derive: the fee payer, the fee ceiling, one
//! compute ceiling per manifest node, the priority multiplier, the
//! validity window, a capped optional message, and the network the
//! composer means it for. The composer signs the whole envelope, so
//! distinct submissions differ in signed content.
//!
//! The tree stays opaque here: its vocabulary and codec live with the
//! effect machinery, and treating it as signed bytes is what keeps this
//! crate a leaf. Producing and verifying the signature binds a hash and a
//! curve, which belongs to the workspace that owns the protocol's
//! cryptography — what this type defines is the signed *content*, through
//! its derived preimage.

use core::fmt;

use hyperscale_hbor::hash::Hasher;
use hyperscale_hbor::{EncodeError, Hash32, Hbor, HborSigned};

use crate::address::PrincipalAddr;
use crate::amount::Quanta;
use crate::execution::{MAX_EVENT_BYTES_PER_TX, MAX_MANIFEST_NODES};
use crate::scheme::{MAX_KEY_BYTES, MAX_SIG_BYTES, SchemeId};
use crate::work::DeclaredWork;

/// The cap on a call body's bytes: the bound envelope tree.
///
/// A wire bound: decode happens before anything is known about a
/// transaction at all, so what stands here is what a decoder will
/// allocate for a stranger. Sized for [`MAX_SUBINTENTS`] subintents at a
/// kilobyte of post-quantum material each, with the tree around them.
pub const MAX_CALL_BYTES: usize = 128 * 1024;

/// The cap on a publish body's bytes: the package artifact, its
/// metadata section included.
///
/// A wire bound on [`MAX_CALL_BYTES`]'s terms, and the deploy ceiling
/// too: an artifact reaches the chain as a publish body, so the two are
/// one constant and cannot drift into a module that admits at deploy
/// but no envelope can carry. Ten times the largest blob the corpus
/// builds, under the per-transaction write ceiling.
pub const MAX_ARTIFACT_BYTES: usize = 256 * 1024;

/// The cap on an envelope's optional message, in bytes. A wire bound,
/// on [`MAX_CALL_BYTES`]'s terms.
pub const MAX_MESSAGE_LEN: usize = 1024;

/// The widest a whole envelope encodes: the larger body at its cap,
/// every signature the envelope may bind at the widest registered
/// scheme, a ceiling per manifest node, the message, and the scalars.
///
/// What a decoder allocates for the envelope as the network carries it,
/// derived from the caps inside it so it moves when they do.
pub const MAX_ENVELOPE_BYTES: usize = MAX_ARTIFACT_BYTES
    + (MAX_SUBINTENTS + 1) * (MAX_KEY_BYTES + MAX_SIG_BYTES + 16)
    + MAX_MANIFEST_NODES * 10
    + MAX_MESSAGE_LEN
    + 256;

const _: () = assert!(
    MAX_CALL_BYTES <= MAX_ARTIFACT_BYTES,
    "the envelope's widest body is the artifact"
);

/// How long a transaction-derived artifact outlives the signed window it
/// was derived from, in milliseconds.
///
/// The default every family takes but one. A subintent stops being
/// admissible at its `validity_end_ms`, so the last transaction that
/// could have bound it is admitted before then and has terminated
/// everywhere a bounded stretch later; a shard's committed cell answers
/// one question whose window closes on the same terms. Past that the
/// cell answers nobody, and no reshape reads either across a cut — both
/// are state, and state migrates with its owner's prefix at every split
/// and merge. The workspace asserts this figure against the bound every
/// other transaction-derived artifact is retained by.
pub const ARTIFACT_GRACE_MS: u64 = 144_000;

/// How long an escrow record and the claim it is decided against outlive
/// the producing intent's signed window, in milliseconds.
///
/// The one exception to [`ARTIFACT_GRACE_MS`], and the reason is that
/// this is the one family a reshape reads across a cut. A record written
/// near a cut is inherited by a successor that must decide it against a
/// claim cell now sitting on some other chain, and every other bound on
/// reshape evidence is one span — so a claim window shorter than that
/// leaves a record nobody can dispose of, its value stranded where
/// presence and absence are both unprovable.
///
/// The floor is far below the figure and is a different argument: a
/// crossing's delivery is admissible to the delivery window's close, one
/// admitted at the last moment has claimed by the finalization delay or
/// never will, and the reclaim that proves it needs the room every
/// abandonment gets to commit. The workspace asserts the figure against
/// the reshape span and the floor against the sum.
pub const CROSSING_GRACE_MS: u64 = 1_500_000;

/// The bound on subintents one envelope may compose, and so on the
/// signatures it carries for them.
///
/// A wire bound on the decode; the signatures themselves are priced,
/// per scheme, by [`DeclaredWork::signature`].
pub const MAX_SUBINTENTS: usize = 32;

/// The most compute one envelope may sign for, in fuel, summed over its
/// per-node ceilings.
///
/// A thirty-second of a block's compute: an execution window of 125 ms
/// on four cores at 2 G fuel/s is a thousand million fuel a block, and
/// one envelope may own that much of it and no more. Held at
/// derivation, where the lowered node count is known, so the sum a
/// block reserves is a figure the protocol chose rather than one the
/// sender did.
pub const MAX_GAS_LIMIT: u64 = 32_000_000;

/// The most a composer may raise their fee by for inclusion, in basis
/// points over the table price: ten times base.
///
/// Held at derivation like the ceilings. The multiplier decides which
/// transactions a block holds and never the order they run in, so a
/// figure past this buys nothing the ceiling does not already.
pub const MAX_PRIORITY_BP: u32 = 100_000;

/// A signed subintent's identity: the hash of its declaration.
///
/// What a nullifier spends and what an escrow cell is keyed by. Defined
/// beside [`TxHash`] because the two are the protocol's two signed
/// identities, and the one this names is the one a composer who is not
/// the signer cannot move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct SubintentHash(pub Hash32);

/// A transaction's identity: the protocol hash of its envelope's signing
/// bytes.
///
/// One value with three jobs that must never diverge: the kernel's
/// canonical ordering key for every commutative-mode decision, the name
/// every consensus artifact — receipt, certificate, provision — attaches
/// to, and the root every fresh derivation and nullifier grows from. It
/// covers exactly what the composer signed — the key and signature sit
/// outside it — so a re-rolled signature over the same content is the
/// same transaction, and two distinct transactions minting the same
/// fresh key is unrepresentable rather than assumed away.
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

/// One bound subintent's signature: the signer's key and their signature
/// over the subintent's declaration hash, in tree order.
///
/// The composer's own signature covers this whole value, so a subintent's
/// scheme, key, and signature are all signed content twice over — once by
/// the subintent's signer and once by the composer binding it.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct SubintentSig {
    /// The scheme the key and signature below belong to.
    pub scheme: SchemeId,
    /// The subintent signer's public key; its derived account address
    /// must match the signer the tree binds.
    #[hbor(max = MAX_KEY_BYTES)]
    pub public_key: Vec<u8>,
    /// The signature over the subintent's declaration hash.
    #[hbor(max = MAX_SIG_BYTES)]
    pub signature: Vec<u8>,
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
    Call(#[hbor(max = MAX_CALL_BYTES)] Vec<u8>),
    /// A module to publish under the composer's own prefix,
    /// its effect metadata section included. Content addressing covers
    /// the whole artifact, so the code and the signatures it declares
    /// cannot drift apart.
    Publish(#[hbor(max = MAX_ARTIFACT_BYTES)] Vec<u8>),
}

/// A transaction: what it asks for and the signing-time choices, under
/// the composer's signature.
///
/// The signature covers the derived preimage — every field but the
/// composer's own key and signature, under the envelope domain — and the
/// hash of that preimage is also the identity fresh derivations root at:
/// distinct signed envelopes never mint the same fresh key.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-vm-envelope-v2")]
pub struct TransactionEnvelope {
    /// The call graph or the package.
    pub body: TransactionBody,
    /// One signature per bound subintent, in tree order.
    #[hbor(max = MAX_SUBINTENTS)]
    pub subintent_sigs: Vec<SubintentSig>,
    /// The fee-paying account — the composer's.
    pub fee_payer: PrincipalAddr,
    /// The signed fee ceiling, in quanta of the protocol resource.
    pub max_fee: Quanta,
    /// The signed compute ceilings, in fuel: one per node of the lowered
    /// manifest, in the order the walk indexes nodes, so a subintent's
    /// nodes sit at the positions the bound tree gives them. A publish
    /// carries one. The sum is held to [`MAX_GAS_LIMIT`] and the count
    /// to the manifest's, both at derivation.
    ///
    /// The composer's, not the subintent signers': whoever pays sets the
    /// ceilings. A subintent's signer fixes what their nodes do, and the
    /// composer fixes what they may cost.
    #[hbor(max = MAX_MANIFEST_NODES)]
    pub gas_limits: Vec<u64>,
    /// The signed priority, in basis points over the table price, held
    /// to [`MAX_PRIORITY_BP`] at derivation. Burned with the rest of the
    /// fee; decides inclusion and never order.
    pub priority_bp: u32,
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
    /// The scheme the composer's key and signature belong to.
    ///
    /// Signed content, unlike the material it describes: a composer says
    /// which scheme they signed under, so one key and signature pair that
    /// happened to validate under two registered schemes could still only
    /// be presented as the one its signer named.
    pub signer_scheme: SchemeId,
    /// The composer's public key, under [`signer_scheme`](Self::signer_scheme).
    #[hbor(unsigned)]
    #[hbor(max = MAX_KEY_BYTES)]
    pub signer: Vec<u8>,
    /// The composer's signature over the hash of
    /// [`signing_bytes`](hyperscale_hbor::HborSigned::signing_bytes).
    #[hbor(unsigned)]
    #[hbor(max = MAX_SIG_BYTES)]
    pub signature: Vec<u8>,
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

    /// The module, for a publish.
    #[must_use]
    pub fn artifact(&self) -> Option<&[u8]> {
        match &self.body {
            TransactionBody::Publish(artifact) => Some(artifact),
            TransactionBody::Call(_) => None,
        }
    }

    /// The digest a signature over this envelope covers.
    ///
    /// Also the transaction's identity — [`TxHash`] is this digest under
    /// the protocol hasher — and the root fresh derivations grow from,
    /// which is what makes "distinct transactions never mint the same
    /// fresh key" structural: an envelope differing only in its unsigned
    /// key and signature fields is the same digest, the same identity,
    /// and the same fresh keys, collapsed by dedup rather than admitted
    /// twice.
    ///
    /// The domain is the preimage's, applied once. The hasher is asked for
    /// an undomained digest of it rather than for a second domain around
    /// the first, because two byte strings for one commitment is what the
    /// preimage encoding exists to prevent.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] when a field exceeds this crate's caps. A decoded
    /// envelope never does — the decoder holds the same bounds — but a
    /// locally built one can carry, say, a publish body over the wire cap,
    /// and a digest over bytes no envelope can carry is a signature over
    /// nothing.
    pub fn signing_digest(&self, hasher: &dyn Hasher) -> Result<[u8; 32], EncodeError> {
        let preimage = self.signing_bytes()?;
        Ok(hasher.hash(&[], &[&preimage]).0)
    }

    /// What every signature this envelope binds declares: its
    /// verification as compute and its material as retention.
    ///
    /// The composer's, plus one per bound subintent. Each scheme is signed
    /// content and each width comes from the registry, so this is a pure
    /// function of what the composer put their name to.
    #[must_use]
    pub fn signatures(&self) -> DeclaredWork {
        self.subintent_sigs
            .iter()
            .fold(DeclaredWork::signature(self.signer_scheme), |total, sig| {
                total.saturating_add(DeclaredWork::signature(sig.scheme))
            })
    }

    /// The compute this envelope signs for whole: the sum of its
    /// per-node ceilings.
    #[must_use]
    pub fn gas_limit_total(&self) -> u64 {
        gas_limit_total(&self.gas_limits)
    }

    /// Whether the signed terms fit a manifest of `nodes` lowered nodes:
    /// one ceiling per node, the sum under [`MAX_GAS_LIMIT`], the
    /// priority under [`MAX_PRIORITY_BP`]. A publish lowers to one node.
    ///
    /// # Errors
    ///
    /// The first term that does not fit.
    pub fn admit_terms(&self, nodes: usize) -> Result<(), TermsRefusal> {
        admit_ceilings(&self.gas_limits, nodes)?;
        if self.priority_bp > MAX_PRIORITY_BP {
            return Err(TermsRefusal::PriorityTooHigh {
                priority_bp: self.priority_bp,
            });
        }
        Ok(())
    }
}

/// The sum of per-node ceilings, saturating: what an envelope buys in
/// compute whole.
#[must_use]
pub fn gas_limit_total(gas_limits: &[u64]) -> u64 {
    gas_limits
        .iter()
        .fold(0u64, |total, ceiling| total.saturating_add(*ceiling))
}

/// The sum of per-node event bounds, saturating: what a manifest's
/// calls may emit between them.
#[must_use]
pub fn event_bytes_total(event_bytes: &[u32]) -> u64 {
    event_bytes
        .iter()
        .fold(0u64, |total, bytes| total.saturating_add(u64::from(*bytes)))
}

/// Whether the methods a manifest calls may emit what a transaction is
/// allowed to emit at all: their bounds summing under
/// [`MAX_EVENT_BYTES_PER_TX`].
///
/// The sum and not each figure: a method is held to its own bound at
/// emit, so what this decides is whether the bounds a manifest gathers
/// are ones a receipt can carry. Answered before the fee, since the
/// declared retention prices the sum and a figure held to the cap would
/// price less than the frames could spend.
///
/// # Errors
///
/// [`TermsRefusal::EventBytesArity`] when the count is not the
/// manifest's, [`TermsRefusal::EventBytesSum`] when the sum is past the
/// cap.
pub fn admit_event_bounds(event_bytes: &[u32], nodes: usize) -> Result<u64, TermsRefusal> {
    // One bound per node, the rule the ceilings answer to. Without it a
    // manifest may arrive with none at all, and an empty vector is the
    // one reading `event_bound` answers with the whole wire cap rather
    // than refusing — so a derivation that skipped this would hand every
    // node 64 KiB the declaration priced at nothing.
    if event_bytes.len() != nodes {
        return Err(TermsRefusal::EventBytesArity {
            nodes,
            bounds: event_bytes.len(),
        });
    }
    let total = event_bytes_total(event_bytes);
    if total > MAX_EVENT_BYTES_PER_TX as u64 {
        return Err(TermsRefusal::EventBytesSum { total });
    }
    Ok(total)
}

/// Whether `gas_limits` fits a manifest of `nodes` lowered nodes: one
/// ceiling per node, and a sum under [`MAX_GAS_LIMIT`].
///
/// # Errors
///
/// [`TermsRefusal::CeilingArity`] when the count is not the manifest's,
/// [`TermsRefusal::CeilingSum`] when the sum is past the bound.
pub fn admit_ceilings(gas_limits: &[u64], nodes: usize) -> Result<(), TermsRefusal> {
    if gas_limits.len() != nodes {
        return Err(TermsRefusal::CeilingArity {
            nodes,
            ceilings: gas_limits.len(),
        });
    }
    let total = gas_limit_total(gas_limits);
    if total > MAX_GAS_LIMIT {
        return Err(TermsRefusal::CeilingSum { total });
    }
    Ok(())
}

/// A signed term the derivation refuses an envelope for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermsRefusal {
    /// The event bounds do not index the lowered manifest one to one.
    EventBytesArity {
        /// Nodes the manifest lowered to.
        nodes: usize,
        /// Bounds the derivation reached.
        bounds: usize,
    },
    /// The ceilings do not index the lowered manifest one to one.
    CeilingArity {
        /// The manifest's node count.
        nodes: usize,
        /// The ceilings the envelope carries.
        ceilings: usize,
    },
    /// The ceilings sum past [`MAX_GAS_LIMIT`].
    CeilingSum {
        /// The sum, saturating.
        total: u64,
    },
    /// The priority is past [`MAX_PRIORITY_BP`].
    PriorityTooHigh {
        /// The signed figure.
        priority_bp: u32,
    },
    /// The methods the manifest calls may emit more between them than
    /// one transaction may emit at all.
    EventBytesSum {
        /// The sum over the manifest's calls, saturating.
        total: u64,
    },
}

impl fmt::Display for TermsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventBytesArity { nodes, bounds } => write!(
                f,
                "the envelope carries {bounds} event bounds against {nodes} manifest nodes"
            ),
            Self::CeilingArity { nodes, ceilings } => write!(
                f,
                "the envelope signs {ceilings} compute ceilings against {nodes} manifest nodes"
            ),
            Self::CeilingSum { total } => write!(
                f,
                "the compute ceilings sum to {total} fuel, past the {MAX_GAS_LIMIT} the protocol admits"
            ),
            Self::PriorityTooHigh { priority_bp } => write!(
                f,
                "the priority of {priority_bp} basis points is past the {MAX_PRIORITY_BP} the protocol admits"
            ),
            Self::EventBytesSum { total } => write!(
                f,
                "the manifest's calls may emit {total} bytes between them, past the \
                 {MAX_EVENT_BYTES_PER_TX} a transaction may emit"
            ),
        }
    }
}

impl std::error::Error for TermsRefusal {}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{HborSigned, assert_canonical, to_vec};

    use super::{
        MAX_EVENT_BYTES_PER_TX, MAX_GAS_LIMIT, MAX_PRIORITY_BP, NetworkId, PrincipalAddr,
        SubintentSig, TermsRefusal, TransactionBody, TransactionEnvelope, admit_event_bounds,
    };
    use crate::{DeclaredWork, SchemeId};

    fn sample() -> TransactionEnvelope {
        TransactionEnvelope {
            body: TransactionBody::Call(vec![1, 2, 3]),
            subintent_sigs: vec![SubintentSig {
                scheme: SchemeId::ED25519,
                public_key: vec![0x11; 32],
                signature: vec![0x22; 64],
            }],
            fee_payer: PrincipalAddr::new([0x33; 31]),
            max_fee: 1_000_000,
            gas_limits: vec![300_000, 200_000],
            priority_bp: 250,
            validity_start_ms: 1_700_000_000_000,
            validity_end_ms: 1_700_000_060_000,
            message: b"hello".to_vec(),
            network: NetworkId(242),
            signer_scheme: SchemeId::ED25519,
            signer: vec![0x44; 32],
            signature: vec![0x55; 64],
        }
    }

    #[test]
    fn the_envelope_is_canonical() {
        assert_canonical(&sample());
    }

    /// Material the envelope carries is material its named scheme claims.
    #[test]
    fn the_carried_material_is_what_the_scheme_registers() {
        let envelope = sample();
        let spec = envelope
            .signer_scheme
            .spec()
            .expect("the sample names a registered scheme");
        assert!(spec.admits(&envelope.signer, &envelope.signature));
        for sig in &envelope.subintent_sigs {
            let spec = sig.scheme.spec().expect("a registered scheme");
            assert!(spec.admits(&sig.public_key, &sig.signature));
        }
    }

    /// Every signature the envelope binds is priced, and each scheme is
    /// priced as the registry has it.
    #[test]
    fn the_declared_signatures_count_every_signature() {
        let ed = DeclaredWork::signature(SchemeId::ED25519);
        let secp = DeclaredWork::signature(SchemeId::SECP256K1);
        let mut envelope = sample();
        assert_eq!(
            envelope.signatures(),
            ed.saturating_add(ed),
            "the composer's signature and the one subintent it binds"
        );

        envelope.subintent_sigs.push(SubintentSig {
            scheme: SchemeId::SECP256K1,
            public_key: vec![0x66; 33],
            signature: vec![0x77; 64],
        });
        assert_eq!(
            envelope.signatures(),
            ed.saturating_add(ed).saturating_add(secp)
        );

        envelope.subintent_sigs.clear();
        assert_eq!(envelope.signatures(), ed);
    }

    /// The scheme is signed content while the material it describes is
    /// not, so re-tagging a key and signature to a second scheme they also
    /// satisfy is a different preimage and loses the signature.
    #[test]
    fn the_scheme_is_signed_and_the_material_is_not() {
        let envelope = sample();
        let mut retagged = envelope.clone();
        retagged.signer_scheme = SchemeId(0xFFFF);
        assert_ne!(
            envelope.signing_bytes().unwrap(),
            retagged.signing_bytes().unwrap()
        );

        let mut rebound = envelope.clone();
        rebound.subintent_sigs[0].scheme = SchemeId(0xFFFF);
        assert_ne!(
            envelope.signing_bytes().unwrap(),
            rebound.signing_bytes().unwrap()
        );
    }

    /// The two fields a signature cannot cover ride the wire and are
    /// absent from the preimage; everything else is signed content.
    #[test]
    fn the_signature_covers_everything_but_itself() {
        let envelope = sample();
        let mut resigned = envelope.clone();
        resigned.signer = vec![0x99; 32];
        resigned.signature = vec![0xAA; 64];
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

    /// The ceilings and the priority are signed content each: moving
    /// one node's ceiling, or the priority alone, moves the preimage.
    #[test]
    fn every_ceiling_and_the_priority_are_signed() {
        let base = sample().signing_bytes().unwrap();
        let mut one_node = sample();
        one_node.gas_limits[1] += 1;
        assert_ne!(one_node.signing_bytes().unwrap(), base);
        let mut priority = sample();
        priority.priority_bp += 1;
        assert_ne!(priority.signing_bytes().unwrap(), base);
    }

    #[test]
    fn the_total_is_the_sum_over_nodes() {
        assert_eq!(sample().gas_limit_total(), 500_000);
        let mut saturating = sample();
        saturating.gas_limits = vec![u64::MAX, 1];
        assert_eq!(saturating.gas_limit_total(), u64::MAX);
    }

    /// One ceiling per lowered node, no more and no fewer.
    #[test]
    fn a_ceiling_count_off_the_manifest_is_refused() {
        let envelope = sample();
        assert_eq!(envelope.admit_terms(2), Ok(()));
        assert_eq!(
            envelope.admit_terms(3),
            Err(TermsRefusal::CeilingArity {
                nodes: 3,
                ceilings: 2,
            })
        );
        assert_eq!(
            envelope.admit_terms(1),
            Err(TermsRefusal::CeilingArity {
                nodes: 1,
                ceilings: 2,
            })
        );
    }

    /// The bound is on the sum, so two nodes each under it can still be
    /// refused together, and the sum is judged saturating.
    #[test]
    fn a_sum_past_the_ceiling_is_refused() {
        let mut envelope = sample();
        envelope.gas_limits = vec![MAX_GAS_LIMIT / 2 + 1, MAX_GAS_LIMIT / 2];
        assert_eq!(
            envelope.admit_terms(2),
            Err(TermsRefusal::CeilingSum {
                total: MAX_GAS_LIMIT + 1,
            })
        );
        envelope.gas_limits = vec![MAX_GAS_LIMIT / 2, MAX_GAS_LIMIT / 2];
        assert_eq!(envelope.admit_terms(2), Ok(()));
        envelope.gas_limits = vec![u64::MAX, u64::MAX];
        assert_eq!(
            envelope.admit_terms(2),
            Err(TermsRefusal::CeilingSum { total: u64::MAX })
        );
    }

    /// The event bounds are judged on their sum for the reason the
    /// ceilings are: each frame is held to its own figure at emit, so
    /// what decides admissibility is whether a receipt could carry what
    /// the frames may spend between them.
    #[test]
    fn event_bounds_summing_past_the_cap_are_refused() {
        let page = u32::try_from(MAX_EVENT_BYTES_PER_TX / 2).expect("half the cap fits u32");
        assert_eq!(
            admit_event_bounds(&[page, page], 2),
            Ok(MAX_EVENT_BYTES_PER_TX as u64)
        );
        assert_eq!(
            admit_event_bounds(&[page, page, 1], 3),
            Err(TermsRefusal::EventBytesSum {
                total: MAX_EVENT_BYTES_PER_TX as u64 + 1,
            })
        );
        assert_eq!(admit_event_bounds(&[], 0), Ok(0));

        // And one bound per node, the rule the ceilings answer to: a
        // manifest arriving with none reaches `event_bound`'s empty
        // reading, which is the whole wire cap at a declared price of
        // nothing.
        assert_eq!(
            admit_event_bounds(&[], 2),
            Err(TermsRefusal::EventBytesArity {
                nodes: 2,
                bounds: 0
            })
        );
        assert_eq!(
            admit_event_bounds(&[page], 2),
            Err(TermsRefusal::EventBytesArity {
                nodes: 2,
                bounds: 1
            })
        );
    }

    #[test]
    fn a_priority_past_the_ceiling_is_refused() {
        let mut envelope = sample();
        envelope.priority_bp = MAX_PRIORITY_BP;
        assert_eq!(envelope.admit_terms(2), Ok(()));
        envelope.priority_bp = MAX_PRIORITY_BP + 1;
        assert_eq!(
            envelope.admit_terms(2),
            Err(TermsRefusal::PriorityTooHigh {
                priority_bp: MAX_PRIORITY_BP + 1,
            })
        );
    }

    /// A publish lowers to one node and carries one ceiling.
    #[test]
    fn a_publish_carries_one_ceiling() {
        let mut publish = sample();
        publish.body = TransactionBody::Publish(vec![9]);
        publish.gas_limits = vec![0];
        assert_eq!(publish.admit_terms(1), Ok(()));
    }
}
