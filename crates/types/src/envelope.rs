//! The signed transaction envelope.
//!
//! The envelope carries the tree — every signed intent, the members
//! each nests with the wiring that fills their sockets, and the records
//! their calls resolve against — as canonical bytes, and beside it the
//! terms no node can derive: the fee payer, the fee ceiling, one
//! compute ceiling per manifest node, the priority multiplier and a
//! capped optional message. The window and the network are the root
//! intent's own header. A publish carries an artifact beside a tree of
//! one root that calls nothing. The root's attesters sign the whole
//! envelope, so distinct submissions differ in signed content.
//!
//! The tree stays opaque here: its vocabulary and codec live with the
//! effect machinery, and treating it as signed bytes is what keeps this
//! crate a leaf. What the terms *are* is this crate's, since a chain
//! reads them without decoding the tree's calls. Producing and verifying
//! the signature binds a hash and a curve, which belongs to the
//! workspace that owns the protocol's cryptography — what this type
//! defines is the signed *content*, through its derived preimage.

use core::fmt;

use hyperscale_hbor::hash::Hasher;
use hyperscale_hbor::{Bytes, Capped, EncodeError, Hash32, Hbor, HborBound, HborShape, HborSigned};

use crate::address::PrincipalAddr;
use crate::amount::Quanta;
use crate::execution::{MAX_EVENT_BYTES_PER_TX, MAX_MANIFEST_NODES};
use crate::scheme::{AccountSigner, MAX_KEY_BYTES, MAX_SIG_BYTES, SchemeId};
use crate::work::DeclaredWork;

/// The cap on a tree's bytes.
///
/// A wire bound: decode happens before anything is known about a
/// transaction at all, so what stands here is what a decoder will
/// allocate for a stranger. Sized for [`MAX_INTENTS`] intents with
/// their graphs, their wiring and the records around them.
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

/// The cap on the terms' optional message, in bytes. A wire bound,
/// on [`MAX_CALL_BYTES`]'s terms.
pub const MAX_MESSAGE_LEN: usize = 1024;

/// The widest a whole envelope encodes: the tree, the artifact and the
/// terms at their caps, every attestation the root may carry at the
/// widest registered scheme, and the scalars.
///
/// What a decoder allocates for the envelope as the network carries it,
/// read off the envelope's own shape so nothing here restates a field.
pub const MAX_ENVELOPE_BYTES: usize = <TransactionEnvelope as HborBound>::MAX_ENCODED_LEN;

/// How long a transaction-derived artifact outlives the signed window it
/// was derived from, in milliseconds.
///
/// An intent stops being admissible at its `validity_end_ms`, so the
/// last transaction that could have carried it is admitted before then and
/// has terminated everywhere a bounded stretch later. Past that the
/// nullifier answers nobody, and no reshape reads it across a cut — it
/// is state, and state migrates with its owner's prefix at every split
/// and merge. The workspace asserts this figure against the bound every
/// other transaction-derived artifact is retained by.
pub const ARTIFACT_GRACE_MS: u64 = 144_000;

/// How long a shard's committed cell for a transaction outlives that
/// transaction's signed window, in milliseconds.
///
/// The one family the VM never writes: a chain writes a committed cell
/// for every transaction its block carries, and another chain's probe
/// reads the absence a refusal leaves. So the span is that chain's to
/// fix, and what is held here is the figure it fixed — swept exactly
/// where the window an absence of it answers in closes. Shorter and a
/// swept cell reads as a shard that never committed, which is a licence
/// to take back a crossing its core may have taken. The workspace
/// asserts the two spellings against each other, and carries the
/// argument for the span beside the window.
pub const COMMITTED_GRACE_MS: u64 = 264_000;

/// The bound on intents one envelope's tree may carry. A wire bound on
/// the decode; the attestations each carries are priced, per scheme,
/// by [`DeclaredWork::signature`].
pub const MAX_INTENTS: usize = 33;

/// The most principals one intent may declare itself attested by, and
/// so the most attestations that stand beside it. A wire bound.
///
/// Room for a threshold rule over a few keys on each of a handful of
/// accounts; every attestation past the first is priced as one more
/// signature, so the ceiling bounds what a decoder allocates rather
/// than what a composer may buy.
pub const MAX_ATTESTATIONS: usize = 8;

/// The most attestations one transaction may carry between its root and
/// every member. Refused at derivation, where the tree is decoded and
/// each attestation is held to its declaration.
///
/// What the byte and compute caps are sized for: every attestation is a
/// verification and its material is retained, so the count rather than
/// the per-intent bound is what one transaction may cost a block. Two
/// per intent at the intent cap, or eight on a handful.
pub const MAX_TX_ATTESTATIONS: usize = 2 * MAX_INTENTS;

/// The widest one attestation encodes: the key and the signature at the
/// widest registered scheme, and the scalars around them.
///
/// Read off [`Attestation`]'s own shape, so it moves when a field or a
/// scheme width does.
pub const MAX_ATTESTATION_BYTES: usize = <Attestation as HborBound>::MAX_ENCODED_LEN;

/// The cap on a tree's bytes as an envelope carries it: the calls,
/// wiring and records at [`MAX_CALL_BYTES`], plus every attestation the
/// transaction may carry at its widest, since a member's ride inside.
///
/// The attestations dominate at the widest scheme and not otherwise; a
/// tree of ed25519 members spends a few kilobytes of this room. What a
/// decoder allocates for a stranger's tree, so the figure is stated
/// against the caps rather than guessed.
pub const MAX_TREE_BYTES: usize = MAX_CALL_BYTES + MAX_TX_ATTESTATIONS * MAX_ATTESTATION_BYTES;

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

/// An intent's identity: the hash of its declaration.
///
/// What a nullifier spends and what an escrow cell is keyed by. Defined
/// beside [`TxHash`] because the two are the protocol's two signed
/// identities, and the one this names is the one a composer who is not
/// the intent's own account cannot move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct IntentHash(pub Hash32);

/// A transaction's identity: the protocol hash of its envelope's signing
/// bytes.
///
/// One value with three jobs that must never diverge: the kernel's
/// canonical ordering key for every commutative-mode decision, the name
/// every consensus artifact — receipt, certificate, provision — attaches
/// to, and the root every fresh derivation and nullifier grows from. It
/// covers exactly what the root's attesters signed — the attestations
/// alone sit outside it, and the principals they stand for are inside
/// the tree — so a re-rolled attestation over the same content is the
/// same transaction, the same content attested by other principals is a
/// different one, and two distinct transactions minting the same fresh
/// key is unrepresentable rather than assumed away.
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

/// One signature standing beside the content it covers, with the key
/// and scheme that produced it.
///
/// Transport rather than signed content: what is signed is the
/// principal the key derives, declared in the intent, so a signature
/// re-keyed or re-tagged afterwards derives another principal and is
/// refused against the declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hbor, HborShape)]
pub struct Attestation {
    /// The scheme the key and signature below belong to.
    pub scheme: SchemeId,
    /// The attesting key. With the scheme it derives the principal
    /// declared at the same position in the intent's `attested_by`, and
    /// an attestation deriving any other is refused. Whether an account
    /// the intent acts as admits that principal is the account's own
    /// cell to say, on its own shard.
    pub public_key: Bytes<MAX_KEY_BYTES>,
    /// The signature over the signing hash of the content the
    /// attestation stands beside: an intent's hash for a member, the
    /// envelope's digest for the root.
    pub signature: Bytes<MAX_SIG_BYTES>,
}

/// The signing-time choices no node can derive, stated once on the
/// envelope beside the tree.
///
/// A function of the assembled manifest — one ceiling per lowered node
/// — so only whoever composes the whole tree can state them, and only
/// the root's attestations cover them. The window and the network are
/// the root's own header. Beside the tree rather than inside any
/// intent: nothing reads terms on a member, and a signed field nothing
/// reads is a field a composer could be made to sign for nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hbor, HborShape)]
pub struct Terms {
    /// The fee-paying account.
    pub fee_payer: PrincipalAddr,
    /// The signed fee ceiling, in quanta of the protocol resource.
    pub max_fee: Quanta,
    /// The signed compute ceilings, in fuel: one per node of the lowered
    /// manifest, in the order the walk indexes nodes, so a member's
    /// nodes sit at the positions the tree gives them. A publish
    /// carries one. The sum is held to [`MAX_GAS_LIMIT`] and the count
    /// to the manifest's, both at derivation.
    ///
    /// The root's, not the members' signers': whoever pays sets the
    /// ceilings. A member's signer fixes what their nodes do, and the
    /// root fixes what they may cost.
    pub gas_limits: Capped<Vec<u64>, MAX_MANIFEST_NODES>,
    /// The signed priority, in basis points over the table price, held
    /// to [`MAX_PRIORITY_BP`] at derivation. Burned with the rest of the
    /// fee; decides inclusion and never order.
    pub priority_bp: u32,
    /// An optional message.
    pub message: Bytes<MAX_MESSAGE_LEN>,
}

impl Terms {
    /// The compute these terms sign for whole: the sum of the per-node
    /// ceilings.
    #[must_use]
    pub fn gas_limit_total(&self) -> u64 {
        gas_limit_total(&self.gas_limits)
    }

    /// Whether the terms fit a manifest of `nodes` lowered nodes: one
    /// ceiling per node, the sum under [`MAX_GAS_LIMIT`], the priority
    /// under [`MAX_PRIORITY_BP`]. A publish lowers to one node.
    ///
    /// # Errors
    ///
    /// The first term that does not fit.
    pub fn admit(&self, nodes: usize) -> Result<(), TermsRefusal> {
        admit_ceilings(&self.gas_limits, nodes)?;
        if self.priority_bp > MAX_PRIORITY_BP {
            return Err(TermsRefusal::PriorityTooHigh {
                priority_bp: self.priority_bp,
            });
        }
        Ok(())
    }
}

/// A signed transaction as the network carries it: the tree, the terms
/// it is paid under, an artifact where it publishes one, and the root's
/// attestations.
///
/// The signature covers the derived preimage — every field but the
/// attestations, under the envelope domain — and the hash of that
/// preimage is the transaction's identity and the root fresh
/// derivations grow from: distinct signed envelopes never mint the same
/// fresh key. The attestations are transport, on the terms
/// [`Attestation`] states: what they pair with is the principals the
/// root intent declares itself attested by, which the tree signs.
#[derive(Debug, Clone, PartialEq, Eq, Hbor, HborShape)]
#[hbor(signing_domain = "hyperscale-vm-envelope-v4")]
pub struct TransactionEnvelope {
    /// The tree, canonically encoded; the effect vocabulary owns the
    /// encoding. A publish's tree is one root that calls nothing. Every
    /// member's attestations ride inside it, beside the intent they
    /// cover.
    pub tree: Bytes<MAX_TREE_BYTES>,
    /// What the transaction is paid and metered under. A function of
    /// the whole tree, so the composer of the root states them, and
    /// signed content: a fee ceiling nobody signed is one anybody could
    /// raise.
    pub terms: Terms,
    /// A module to publish under the composer's own prefix, its effect
    /// metadata section included. Content addressing covers the whole
    /// artifact, so the code and the signatures it declares cannot
    /// drift apart. Every other field of the envelope means the same
    /// thing for a publish as for a call, which is why publishing rides
    /// this envelope rather than a body of its own: fee assurance,
    /// engagement, and tick settlement are the same machinery either
    /// way.
    pub artifact: Option<Bytes<MAX_ARTIFACT_BYTES>>,
    /// The root's attestations over the hash of
    /// [`signing_bytes`](hyperscale_hbor::HborSigned::signing_bytes),
    /// one per principal the root intent declares itself attested by,
    /// in that order. The one field the preimage leaves out.
    #[hbor(unsigned)]
    pub signatures: Capped<Vec<Attestation>, MAX_ATTESTATIONS>,
}

impl TransactionEnvelope {
    /// The digest a signature over this envelope covers.
    ///
    /// Also the transaction's identity — [`TxHash`] is this digest under
    /// the protocol hasher — and the root fresh derivations grow from,
    /// which is what makes "distinct transactions never mint the same
    /// fresh key" structural: an envelope differing only in its unsigned
    /// signature is the same digest, the same identity, and the same
    /// fresh keys, collapsed by dedup rather than admitted twice.
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
    /// locally built one can carry, say, an artifact over the wire cap,
    /// and a digest over bytes no envelope can carry is a signature over
    /// nothing.
    pub fn signing_digest(&self, hasher: &dyn Hasher) -> Result<[u8; 32], EncodeError> {
        let preimage = self.signing_bytes()?;
        Ok(hasher.hash(&[], &[&preimage]).0)
    }
}

/// One attestation over `hash` by `key`.
///
/// The scheme is stamped beside the material it describes, so a signer's
/// key and their claim about which curve produced it are written in one
/// place and cannot drift apart.
///
/// # Panics
///
/// On a signer whose key or signature outsizes the widest the registry
/// holds, which no registered scheme produces.
#[must_use]
pub fn attest<S: AccountSigner + ?Sized>(key: &S, hash: &[u8; 32]) -> Attestation {
    // The registry sizes the caps from the widest scheme it holds, so a
    // registered signer's key and signature fit by construction.
    Attestation {
        scheme: key.scheme(),
        public_key: Bytes::new(key.public_key_bytes()).expect("a registered scheme's key fits"),
        signature: Bytes::new(key.sign_digest(hash)).expect("a registered scheme's signature fits"),
    }
}

/// What verifying `attestations` costs, each priced as its scheme is
/// registered, saturating.
#[must_use]
pub fn attestation_work<'a>(
    attestations: impl IntoIterator<Item = &'a Attestation>,
) -> DeclaredWork {
    attestations
        .into_iter()
        .fold(DeclaredWork::default(), |total, attestation| {
            total.saturating_add(DeclaredWork::signature(attestation.scheme))
        })
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
    use hyperscale_hbor::{Capped, HborSigned, assert_canonical, to_vec};

    use super::{
        Attestation, MAX_EVENT_BYTES_PER_TX, MAX_GAS_LIMIT, MAX_PRIORITY_BP, PrincipalAddr, Terms,
        TermsRefusal, TransactionEnvelope, admit_event_bounds, attestation_work,
    };
    use crate::{DeclaredWork, SchemeId};

    fn sample() -> TransactionEnvelope {
        TransactionEnvelope {
            tree: vec![1, 2, 3].try_into().unwrap(),
            terms: terms(),
            artifact: None,
            signatures: vec![Attestation {
                scheme: SchemeId::ED25519,
                public_key: vec![0x44; 32].try_into().unwrap(),
                signature: vec![0x55; 64].try_into().unwrap(),
            }]
            .try_into()
            .unwrap(),
        }
    }

    fn terms() -> Terms {
        Terms {
            fee_payer: PrincipalAddr::new([0x33; 31]),
            max_fee: 1_000_000,
            gas_limits: vec![300_000, 200_000].try_into().unwrap(),
            priority_bp: 250,
            message: b"hello".to_vec().try_into().unwrap(),
        }
    }

    #[test]
    fn the_envelope_is_canonical() {
        assert_canonical(&sample());
        assert_canonical(&terms());
    }

    /// Material an attestation carries is material its named scheme
    /// claims.
    #[test]
    fn the_carried_material_is_what_the_scheme_registers() {
        for attestation in &sample().signatures {
            let spec = attestation.scheme.spec().expect("a registered scheme");
            assert!(spec.admits(&attestation.public_key, &attestation.signature));
        }
    }

    /// Every attestation is priced, and each scheme is priced as the
    /// registry has it.
    #[test]
    fn the_declared_signatures_count_every_attestation() {
        let ed = DeclaredWork::signature(SchemeId::ED25519);
        let secp = DeclaredWork::signature(SchemeId::SECP256K1);
        let mut envelope = sample();
        assert_eq!(attestation_work(&envelope.signatures), ed);

        envelope
            .signatures
            .push(Attestation {
                scheme: SchemeId::SECP256K1,
                public_key: vec![0x66; 33].try_into().unwrap(),
                signature: vec![0x77; 64].try_into().unwrap(),
            })
            .unwrap();
        assert_eq!(
            attestation_work(&envelope.signatures),
            ed.saturating_add(secp)
        );

        envelope.signatures = Capped::empty();
        assert_eq!(
            attestation_work(&envelope.signatures),
            DeclaredWork::default()
        );
    }

    /// The attestations are the one field the preimage leaves out; they
    /// ride the wire and nothing else. Everything else is signed
    /// content.
    #[test]
    fn the_signature_covers_everything_but_the_attestations() {
        let envelope = sample();
        let mut resigned = envelope.clone();
        let mut first = resigned.signatures[0].clone();
        first.signature = vec![0xAA; 64].try_into().unwrap();
        first.scheme = SchemeId(0xFFFF);
        resigned.signatures = vec![first].try_into().unwrap();
        assert_eq!(
            envelope.signing_bytes().unwrap(),
            resigned.signing_bytes().unwrap()
        );
        assert_ne!(to_vec(&envelope).unwrap(), to_vec(&resigned).unwrap());

        let mut retreed = envelope.clone();
        retreed.tree = vec![1, 2, 3, 4].try_into().unwrap();
        assert_ne!(
            retreed.signing_bytes().unwrap(),
            envelope.signing_bytes().unwrap()
        );
        let mut repriced = envelope.clone();
        repriced.terms.max_fee += 1;
        assert_ne!(
            repriced.signing_bytes().unwrap(),
            envelope.signing_bytes().unwrap()
        );
    }

    /// The artifact is signed content: the same tree with and without
    /// one, or with another one, is another transaction.
    #[test]
    fn the_artifact_is_signed() {
        let call = sample();
        let mut publish = sample();
        publish.artifact = Some(vec![9].try_into().unwrap());
        assert_ne!(
            call.signing_bytes().unwrap(),
            publish.signing_bytes().unwrap()
        );
        let mut other = sample();
        other.artifact = Some(vec![8].try_into().unwrap());
        assert_ne!(
            other.signing_bytes().unwrap(),
            publish.signing_bytes().unwrap()
        );
    }

    #[test]
    fn the_total_is_the_sum_over_nodes() {
        assert_eq!(terms().gas_limit_total(), 500_000);
        let mut saturating = terms();
        saturating.gas_limits = vec![u64::MAX, 1].try_into().unwrap();
        assert_eq!(saturating.gas_limit_total(), u64::MAX);
    }

    /// One ceiling per lowered node, no more and no fewer.
    #[test]
    fn a_ceiling_count_off_the_manifest_is_refused() {
        let terms = terms();
        assert_eq!(terms.admit(2), Ok(()));
        assert_eq!(
            terms.admit(3),
            Err(TermsRefusal::CeilingArity {
                nodes: 3,
                ceilings: 2,
            })
        );
        assert_eq!(
            terms.admit(1),
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
        let mut terms = terms();
        terms.gas_limits = vec![MAX_GAS_LIMIT / 2 + 1, MAX_GAS_LIMIT / 2]
            .try_into()
            .unwrap();
        assert_eq!(
            terms.admit(2),
            Err(TermsRefusal::CeilingSum {
                total: MAX_GAS_LIMIT + 1,
            })
        );
        terms.gas_limits = vec![MAX_GAS_LIMIT / 2, MAX_GAS_LIMIT / 2]
            .try_into()
            .unwrap();
        assert_eq!(terms.admit(2), Ok(()));
        terms.gas_limits = vec![u64::MAX, u64::MAX].try_into().unwrap();
        assert_eq!(
            terms.admit(2),
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
        let mut terms = terms();
        terms.priority_bp = MAX_PRIORITY_BP;
        assert_eq!(terms.admit(2), Ok(()));
        terms.priority_bp = MAX_PRIORITY_BP + 1;
        assert_eq!(
            terms.admit(2),
            Err(TermsRefusal::PriorityTooHigh {
                priority_bp: MAX_PRIORITY_BP + 1,
            })
        );
    }

    /// A publish lowers to one node and carries one ceiling.
    #[test]
    fn a_publish_carries_one_ceiling() {
        let mut terms = terms();
        terms.gas_limits = vec![0].try_into().unwrap();
        assert_eq!(terms.admit(1), Ok(()));
    }
}
