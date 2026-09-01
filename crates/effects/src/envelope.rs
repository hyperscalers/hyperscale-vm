//! The bound envelope tree: a root intent composed with separately
//! signed subintents through the sockets they declare, and the
//! nullifier vocabulary that makes a committed subintent once-only.
//!
//! A subintent's signer signs an [`IntentDecl`] — a graph over the
//! sockets it declares. A socket carries either of the two things that
//! cross an intent boundary: a value edge, which exactly one node
//! argument consumes, or a proof, which as many of the intent's nodes
//! present as ask for it. The composer fills every socket from another
//! intent's node and signs the whole envelope; nothing about the tree
//! is renegotiated at admission.
//!
//! [`admit_tree`] flattens the tree into one routing manifest: intents
//! keep their author order and their sockets interleave them
//! deterministically, so a node lands after whatever fills every socket
//! it reaches — the ones its arguments consume and the ones its
//! evidence presents alike. A composition admitting no such order is
//! rejected.
//!
//! Committing a subintent writes a kernel nullifier substate at the
//! canonical address `signer_prefix | H(nullifier_role, subintent_hash)`
//! — computable, hence declarable, hence a creation conflict: two
//! compositions racing one subintent contend on the nullifier key and
//! exactly one commits. Cancellation is the signer spending the
//! nullifier under their own prefix.

use std::collections::BTreeSet;

use hyperscale_hbor::{Hbor, from_slice, to_vec};
pub use hyperscale_vm_types::MAX_SUBINTENTS;
use hyperscale_vm_types::{
    Address, Effect, EffectTarget, MAX_MANIFEST_NODES, Mode, Moves, NULLIFIER_GRACE_MS, NetworkId,
    PrincipalAddr, ResourceAddr, SubintentHash, SubstateKey, SweepBucket, TxHash,
};

use crate::PACKAGE_SLOT_BASE;
use crate::admission::{
    AdmissionError, Admitted, IntentView, MAX_SOCKETS, admit_intents, check_instance_value_depth,
    check_value_depth,
};
use crate::claim::Claim;
use crate::dsl::PresentedGrants;
use crate::graph::{Constraint, EdgeRef, ManifestGraph};
use crate::hash::Hasher;
use crate::instance::InstanceMeta;
use crate::manifest::ManifestHash;
use crate::records::{ChainRecords, Composed};
use crate::resource::ResourceMeta;
use crate::route::{Routing, ShardResolver, route};
use crate::types::{SlotId, bucketed_child_key};

/// The kernel-reserved role of subintent nullifier substates under a
/// signer's prefix.
///
/// The top of the role space is the kernel's, as the bottom is the
/// protocol vocabulary's and the middle is where packages number from.
pub const NULLIFIER_SLOT: SlotId = SlotId(0xFFFF);

/// The kernel-reserved role of escrow record substates under the
/// producing node's target.
///
/// What the shard issuing a crossing writes: the resource and the amount
/// that left it. The record is the memo a reclaim reads, which is why
/// nothing has to remember a diff.
pub const ESCROW_RECORD_SLOT: SlotId = SlotId(0xFFFD);

/// The kernel-reserved role of escrow claim substates under the claiming
/// node's target.
///
/// What the shard taking a crossing writes. The record says value was
/// issued and never that it is still available; this is what says it was
/// taken, and it is what makes exactly one of the core's claim and the
/// producer's reclaim happen.
pub const ESCROW_CLAIM_SLOT: SlotId = SlotId(0xFFFE);

/// The reserved role of committed-transaction substates under a shard's
/// own owner.
///
/// What a shard writes at block commit for every transaction the block
/// carries: the fact that it committed it, provable and refutable
/// against the state root every header carries. No kernel writes one;
/// the chain does, and a reader holding nothing but the leaf can tell
/// it from any other cell and tell when it stops being needed.
pub const COMMITTED_TX_SLOT: SlotId = SlotId(0xFFFC);

// Held at compile time rather than by a test: every side is a constant,
// so a kernel cell colliding with a package's own — or with another
// kernel family — is a thing the build can refuse outright.
const _: () = assert!(NULLIFIER_SLOT.0 > PACKAGE_SLOT_BASE);
const _: () = assert!(ESCROW_RECORD_SLOT.0 > PACKAGE_SLOT_BASE);
const _: () = assert!(ESCROW_CLAIM_SLOT.0 > PACKAGE_SLOT_BASE);
const _: () = assert!(COMMITTED_TX_SLOT.0 > PACKAGE_SLOT_BASE);
const _: () = assert!(NULLIFIER_SLOT.0 != ESCROW_RECORD_SLOT.0);
const _: () = assert!(NULLIFIER_SLOT.0 != ESCROW_CLAIM_SLOT.0);
const _: () = assert!(ESCROW_RECORD_SLOT.0 != ESCROW_CLAIM_SLOT.0);
const _: () = assert!(COMMITTED_TX_SLOT.0 != NULLIFIER_SLOT.0);
const _: () = assert!(COMMITTED_TX_SLOT.0 != ESCROW_RECORD_SLOT.0);
const _: () = assert!(COMMITTED_TX_SLOT.0 != ESCROW_CLAIM_SLOT.0);

/// A shaped opening an intent declares for something it cannot supply
/// itself, which the composition carrying it fills.
///
/// Shaped, which is what the name is for: the declaration says what may
/// arrive, and a binding that does not fit is refused rather than
/// accepted and dealt with. Two things cross an intent boundary and
/// both cross this way — **the declaration says what**, and its signer
/// signs that; **the composition says whose**, and nothing about it is
/// signed by the party who declared the socket. That split is the whole
/// of what makes a subintent composable without its signer having met
/// the composer.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum Socket {
    /// A value edge carrying exactly this resource, under the declaring
    /// intent's own constraints.
    Value {
        /// The resource the edge must carry.
        resource: ResourceAddr,
        /// The declaring intent's constraints on it — the same language
        /// that constrains ordinary graph edges.
        constraints: Vec<Constraint>,
    },
    /// A proof carrying exactly this claim, which this intent's own
    /// nodes present through [`crate::EvidenceRef::Socket`].
    ///
    /// The claim is the declaration's, so a holder signs *which
    /// authority they are asking for* and never who supplies it — and
    /// admission presents that claim alone, never whatever else the
    /// proving node happened to prove, so a composition cannot smuggle
    /// authority into an intent its signer never offered.
    Authority(Claim),
}

/// The terms an intent is admissible under: the network it was declared
/// for and the window it stands in.
///
/// Its signer signs these with the rest of the declaration, so a
/// composition can neither retarget an intent nor outlive the window the
/// signer offered it for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct IntentHeader {
    /// The network this intent is declared for.
    ///
    /// Signed by the intent's own signer rather than inherited from the
    /// composition, so a subintent binds only into an envelope for the
    /// network its signer named.
    pub network: NetworkId,
    /// The window's inclusive start, in weighted-time milliseconds.
    ///
    /// Milliseconds rather than a range type: what a clock reading
    /// *means* is the workspace's, and this crate holds the number its
    /// signer signed. The envelope states its own window the same way.
    pub validity_start_ms: u64,
    /// The window's exclusive end.
    ///
    /// What ends the intent's admissibility, and so what ends the life
    /// of the nullifier that makes a subintent once-only. A signer who
    /// names no window is offering something forever.
    pub validity_end_ms: u64,
    /// What distinguishes this intent from an identical one.
    ///
    /// A declaration's identity is its content, and its nullifier is
    /// derived from that identity — so without this, one signer cannot
    /// stand behind the same offer twice inside one window: the second
    /// carries the first's nullifier and is refused as already spent.
    /// A signer who means two offers picks two values, and a signer who
    /// means one leaves it alone.
    pub discriminator: u64,
}

/// One intent's declared form: a graph over typed sockets.
///
/// The root intent and every subintent share this shape; a subintent's
/// signer signs exactly this, so [`IntentDecl::hash`] is the subintent's
/// identity whatever composition later carries it. Outputs the graph
/// does not consume internally are the intent's yields — the composition
/// must bind every one to some intent's socket.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct IntentDecl {
    /// What the intent is admissible under, as against what it does.
    ///
    /// Grouped rather than flat because these are the terms that bound
    /// the intent and the nullifier it spends, and because the preimage
    /// then covers the header whole — a term added here cannot go
    /// unsigned.
    pub header: IntentHeader,
    /// The intent's invocation graph; arguments may reference the
    /// sockets via [`crate::GraphArg::Socket`].
    pub graph: ManifestGraph,
    /// The sockets this intent declares. A value socket is consumed by
    /// exactly one node argument; an authority socket is presented by as
    /// many nodes as ask for it.
    #[hbor(max = MAX_SOCKETS)]
    pub sockets: Vec<Socket>,
}

const DOMAIN_SUBINTENT: &[u8] = b"hyperscale-vm/subintent";
const DOMAIN_ENVELOPE_TREE: &[u8] = b"hyperscale-vm/envelope-tree";

impl IntentDecl {
    /// The declaration's identity through the hasher seam: the header,
    /// the graph hash, and every socket it declares, each one part
    /// carrying its canonical encoding.
    ///
    /// The fields are destructured rather than read one at a time, and
    /// the header enters whole through its own encoding, because
    /// everything the declaration carries is content its signer signs. A
    /// field this preimage misses is a field in the format, in the
    /// encoding, and unsigned — so a new one either fails the build here
    /// or rides the header's encoding, and never passes silently.
    ///
    /// # Panics
    ///
    /// Hashed declarations pass the depth gate first, as
    /// [`Value::canonical_bytes`](crate::types::Value::canonical_bytes)
    /// requires of the literals the graph hash feeds on.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> SubintentHash {
        let Self {
            header,
            graph,
            sockets,
        } = self;
        let graph = graph.hash(hasher);
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(2 + sockets.len());
        parts.push(to_vec(header).expect("a header is three scalars"));
        parts.push(graph.0.0.to_vec());
        for socket in sockets {
            parts.push(to_vec(socket).expect("a socket is shallow"));
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        SubintentHash(hasher.hash(DOMAIN_SUBINTENT, &refs))
    }
}

/// What a composition puts in one socket.
///
/// The composer's choice, covered by the envelope identity and never by
/// the declaring intent's own hash — which is what lets one signed
/// subintent be carried by any composition that can fill its sockets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Binding {
    /// The `output`-th edge of node `producer` inside `intent`.
    Value {
        /// The producing intent: `0` names the root, `i + 1` names
        /// subintent `i`.
        intent: u32,
        /// The produced edge within that intent's graph.
        edge: EdgeRef,
    },
    /// The claim node `producer` of `intent` proves.
    Authority {
        /// The producing intent, numbered as above.
        intent: u32,
        /// The proving node within that intent's graph.
        producer: u32,
    },
}

impl Binding {
    /// The intent whose node this binding names.
    #[must_use]
    pub const fn intent(self) -> u32 {
        match self {
            Self::Value { intent, .. } | Self::Authority { intent, .. } => intent,
        }
    }

    /// The node within it.
    #[must_use]
    pub const fn producer(self) -> u32 {
        match self {
            Self::Value { edge, .. } => edge.producer,
            Self::Authority { producer, .. } => producer,
        }
    }
}

/// A subintent bound into an envelope.
///
/// Carries the signed declaration, the signer's account prefix, and one
/// binding per socket. The bindings are the composer's choice and are
/// covered by the envelope identity, never by the subintent's own hash.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Subintent {
    /// What the subintent's signer signed.
    pub decl: IntentDecl,
    /// The signer's account prefix — the owner of the nullifier.
    pub signer: PrincipalAddr,
    /// The composition's binding for each socket.
    #[hbor(max = MAX_SOCKETS)]
    pub bindings: Vec<Binding>,
}

/// The bound envelope tree admission runs over: the composer's root
/// intent plus every bound subintent.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct EnvelopeTree {
    /// The composer's own intent.
    pub root: IntentDecl,
    /// The composition's binding for each root socket.
    #[hbor(max = MAX_SOCKETS)]
    pub root_bindings: Vec<Binding>,
    /// The bound subintents, in envelope order.
    #[hbor(max = MAX_SUBINTENTS)]
    pub subintents: Vec<Subintent>,
    /// The creation-fixed records of the component targets the tree
    /// names beyond what the genesis registry serves — each registered,
    /// at derivation, at exactly the address it derives.
    ///
    /// Inside the signed tree, so what an envelope's calls resolve
    /// against is covered by its identity. A record no target names is
    /// dead weight its composer paid to carry, not a refusal.
    #[hbor(max = MAX_MANIFEST_NODES)]
    pub instances: Vec<InstanceMeta>,
    /// The granted-rule records of the resources the tree's gates name —
    /// each registered, at derivation, at exactly the address it
    /// derives, on the terms `instances` states.
    ///
    /// Inside the signed tree for the same reason: what a grant leaf
    /// resolves against is covered by the envelope's identity, and the
    /// composer pays the record's bytes.
    #[hbor(max = MAX_MANIFEST_NODES)]
    pub resources: Vec<ResourceMeta>,
}

impl EnvelopeTree {
    /// The tree's own identity — the fallback for callers that sign
    /// nothing beyond the tree. A protocol envelope signing more (fee
    /// terms, validity windows) derives its identity from
    /// the full signed form and passes that to [`admit_tree`] instead.
    ///
    /// # Panics
    ///
    /// Hashed trees pass the depth gate first, as
    /// [`Value::canonical_bytes`](crate::types::Value::canonical_bytes)
    /// requires of the literals the graph hashes feed on.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> ManifestHash {
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(3 + 3 * self.subintents.len());
        parts.push(self.root.hash(hasher).0.0.to_vec());
        parts.push(to_vec(&self.root_bindings).expect("bindings are flat"));
        for subintent in &self.subintents {
            parts.push(subintent.decl.hash(hasher).0.0.to_vec());
            parts.push(subintent.signer.to_bytes().to_vec());
            parts.push(to_vec(&subintent.bindings).expect("bindings are flat"));
        }
        // What the tree's calls resolve against is part of what was
        // composed, so two trees differing only here are two identities.
        parts.push(to_vec(&self.instances).expect("instance records are wire-bounded values"));
        parts.push(to_vec(&self.resources).expect("resource records are wire-bounded values"));
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        ManifestHash(hasher.hash(DOMAIN_ENVELOPE_TREE, &refs))
    }
}

/// The canonical nullifier key for a signed subintent under its signer:
/// `signer_prefix | expiry_bucket | H(nullifier_role, subintent_hash,
/// expiry)`.
///
/// The expiry is part of the identity rather than only of the value, so
/// a spend cannot claim a life the declaration does not give it: the key
/// a false expiry names is not the key the screen expects, and the
/// declaration does not cover it.
///
/// It is in the identity twice over — hashed into the body and, coarsely,
/// leading the local half — so a nullifier answers *when* it stops being
/// needed from its key alone, and one signer's nullifiers for one bucket
/// are a contiguous leaf-key range for a sweep to walk. Both halves come
/// from the one `expiry_ms` argument, so neither can drift from the
/// other.
#[must_use]
pub fn nullifier_key(
    hasher: &dyn Hasher,
    signer: impl Into<Address>,
    subintent: SubintentHash,
    expiry_ms: u64,
) -> SubstateKey {
    bucketed_child_key(
        hasher,
        signer,
        NULLIFIER_SLOT,
        SweepBucket::of(expiry_ms),
        &[subintent.0.0.to_vec(), expiry_ms.to_le_bytes().to_vec()],
    )
}

/// What a nullifier cell holds: the subintent it spends, the transaction
/// that spent it, and when the record stops being needed.
///
/// Self-describing, and keyed by what it says: `nullifier_key` re-derives
/// this cell's own key from `subintent` and `expiry_ms` under the
/// signer's prefix, so a reader holding nothing but the leaf can tell a
/// nullifier from any other cell and can tell whether it is still owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct NullifierCell {
    /// The subintent this spend consumed.
    pub subintent: SubintentHash,
    /// The transaction that consumed it.
    pub tx: TxHash,
    /// When no chain can still be deciding a spend of the subintent:
    /// its `validity_end_ms` plus [`NULLIFIER_GRACE_MS`].
    pub expiry_ms: u64,
}

impl NullifierCell {
    /// The cell's committed bytes.
    ///
    /// The type owns its encoding, so the kernel writing one and a
    /// reader deciding what it is agree by construction rather than by
    /// two call sites staying in step.
    ///
    /// # Panics
    ///
    /// Never: the value is three scalars.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("a nullifier cell is three scalars")
    }
}

/// The canonical committed-transaction key for `tx` under the committing
/// shard's own owner: `shard_prefix | expiry_bucket | H(committed_tx_role,
/// tx, expiry)`.
///
/// Bucketed like the nullifier, so a shard's committed set for one
/// bucket is a contiguous range a sweep walks, and self-describing like
/// it, so a leaf answers when it stops being needed on its own. The
/// expiry is the transaction's own validity end plus the grace, which a
/// reader derives from signed content: a prober asking whether a shard
/// committed a transaction needs nothing but the transaction and the
/// shard to name the cell.
///
/// The material here is chosen by a composer and not by the owner,
/// which [`bucketed_child_key`] warns against on its 48-bit birthday
/// bound. It is admissible for this family and for this family alone,
/// because a collision can only make the cell present, never absent: a
/// second transaction landing on the key overwrites a value with one
/// that still derives the key, both share the bucket the sweep retires
/// together, and presence is never what the cell is asked to prove.
/// What it proves is absence, and nothing a composer can grind produces
/// a missing leaf.
#[must_use]
pub fn committed_tx_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    tx: TxHash,
    expiry_ms: u64,
) -> SubstateKey {
    bucketed_child_key(
        hasher,
        owner,
        COMMITTED_TX_SLOT,
        SweepBucket::of(expiry_ms),
        &[tx.0.0.to_vec(), expiry_ms.to_le_bytes().to_vec()],
    )
}

/// What a committed-transaction cell holds: the transaction, and when
/// the record stops being needed.
///
/// Self-describing, and keyed by what it says: [`committed_tx_key`]
/// re-derives this cell's own key from `tx` and `expiry_ms` under the
/// shard's owner, so a reader holding nothing but the leaf can tell it
/// from any other cell and can tell whether it is still owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct CommittedTxCell {
    /// The transaction the shard committed.
    pub tx: TxHash,
    /// When no chain can still be asking whether it was committed: its
    /// `validity_end_ms` plus [`NULLIFIER_GRACE_MS`].
    pub expiry_ms: u64,
}

impl CommittedTxCell {
    /// The cell's committed bytes.
    ///
    /// # Panics
    ///
    /// Never: the value is two scalars.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("a committed-transaction cell is two scalars")
    }
}

/// The canonical escrow record key for one value edge, under the
/// producing node's target.
///
/// Keyed by what its signer signed and by nothing the composition
/// chose. `intent` is the declaration hash of the intent the producing
/// node belongs to and `local` is that node's index inside it — never
/// the transaction hash and never the flattened manifest index, both of
/// which a composer who is not this cell's owner assembles.
///
/// That is what admits the bucketed form here. It spends four of the
/// local half's sixteen bytes, so what is left is a 96-bit owner-salted
/// body and a 48-bit birthday bound — affordable only where both halves
/// of a collision need one signer's signature, which is exactly what
/// keying by the signing intent restores. Two escrow cells a grinder can
/// collide are then two whose material the grinder chose, and reaching
/// somebody else's is a second preimage again.
///
/// The expiry is in the identity twice over — hashed into the body and,
/// coarsely, leading the local half — on [`nullifier_key`]'s terms and
/// for its reasons.
#[must_use]
pub fn escrow_record_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    intent: SubintentHash,
    local: u32,
    output: u32,
    expiry_ms: u64,
) -> SubstateKey {
    escrow_key(
        hasher,
        owner,
        ESCROW_RECORD_SLOT,
        intent,
        local,
        output,
        expiry_ms,
    )
}

/// The canonical escrow claim key for one value edge, under the target
/// of the node that took it.
///
/// The same material as [`escrow_record_key`] under a different owner
/// and a different role, which is what lets one crossing be named by
/// both shards without either consulting placement. The owner is what
/// distinguishes two consumers of one output; the role is what keeps a
/// claim from ever aliasing the record it claims.
#[must_use]
pub fn escrow_claim_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    intent: SubintentHash,
    local: u32,
    output: u32,
    expiry_ms: u64,
) -> SubstateKey {
    escrow_key(
        hasher,
        owner,
        ESCROW_CLAIM_SLOT,
        intent,
        local,
        output,
        expiry_ms,
    )
}

fn escrow_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    slot: SlotId,
    intent: SubintentHash,
    local: u32,
    output: u32,
    expiry_ms: u64,
) -> SubstateKey {
    bucketed_child_key(
        hasher,
        owner,
        slot,
        SweepBucket::of(expiry_ms),
        &[
            intent.0.0.to_vec(),
            local.to_le_bytes().to_vec(),
            output.to_le_bytes().to_vec(),
            expiry_ms.to_le_bytes().to_vec(),
        ],
    )
}

/// What an escrow record cell holds: the value that left, the edge it
/// left on, and when the record stops being needed.
///
/// Self-describing on [`NullifierCell`]'s terms: the value re-derives the
/// key, so a reader holding nothing but the leaf can tell what it is and
/// whether it is still owed. That is also what makes the pair sweepable,
/// since the sweep asks the cell rather than the writer.
///
/// The edge is named here as well as in the key because a reclaim reads
/// this cell and nothing else — the producing shard credits the resource
/// and the amount back from the leaf alone, holding neither the
/// transaction nor a window of them. So is the cell the value left: a
/// reclaim credits it, and no rule the kernel could hold says which of
/// an owner's cells that is — an account's vault for a resource is the
/// account package's own layout, and a component's is another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct CrossingCell {
    /// The resource that crossed.
    pub resource: ResourceAddr,
    /// How much of it.
    pub amount: u128,
    /// The cell the value was reserved from, and the one a reclaim
    /// credits.
    pub origin: SubstateKey,
    /// The signed intent the producing node belongs to.
    pub intent: SubintentHash,
    /// That node's index within its own intent.
    pub local: u32,
    /// Which of its outputs the edge carried.
    pub output: u32,
    /// When no chain can still be claiming the crossing: the producing
    /// intent's own window end plus the retention grace — the intent's,
    /// not the transaction's, so the composer chooses no part of it.
    pub expiry_ms: u64,
}

impl CrossingCell {
    /// The cell's committed bytes.
    ///
    /// # Panics
    ///
    /// Never: the value is scalars and one address.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("a crossing cell is scalars and an address")
    }

    /// A record read back off the leaf, or nothing for bytes that are
    /// not one — the type owns its decoding for the reason it owns its
    /// encoding.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        from_slice(bytes).ok()
    }
}

/// What an escrow claim cell holds: which transaction took the crossing,
/// and when the record of that stops being needed.
///
/// The transaction rather than the intent, because what a reader wants of
/// a claim is *who took it* — the edge it names is already the key's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct ClaimCell {
    /// The transaction that took the crossing.
    pub tx: TxHash,
    /// When the claim stops being owed, on the record's own terms.
    pub expiry_ms: u64,
}

impl ClaimCell {
    /// The cell's committed bytes.
    ///
    /// # Panics
    ///
    /// Never: the value is two scalars.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("a claim cell is two scalars")
    }
}

/// One escrow cell: where it sits, and what identifies it.
///
/// The key and the fields that derive it, built together so the two
/// cannot disagree. That matters because a sweepable cell answers *when
/// do I stop being needed* from its own value — the sweep re-derives the
/// key from what the leaf holds — so a cell whose value does not
/// reproduce its key is one no sweep ever reaches, which is a leak
/// nothing announces.
///
/// The kernel is handed these rather than deriving them. Its hashing
/// seam takes bytes and not a domain, so it could not derive a child key
/// if it wanted to; and deriving one is the parent's job anyway, since
/// two shards divide one manifest separately and have to reach the same
/// cell without consulting each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossingSite {
    key: SubstateKey,
    intent: SubintentHash,
    local: u32,
    output: u32,
    expiry_ms: u64,
}

impl CrossingSite {
    /// The record cell of the edge `local` produces, under the producing
    /// node's target.
    #[must_use]
    pub fn record(
        hasher: &dyn Hasher,
        owner: impl Into<Address>,
        intent: SubintentHash,
        local: u32,
        output: u32,
        expiry_ms: u64,
    ) -> Self {
        let owner = owner.into();
        Self {
            key: escrow_record_key(hasher, owner, intent, local, output, expiry_ms),
            intent,
            local,
            output,
            expiry_ms,
        }
    }

    /// The claim cell for that edge, under the target of whatever takes
    /// it.
    #[must_use]
    pub fn claim(
        hasher: &dyn Hasher,
        owner: impl Into<Address>,
        intent: SubintentHash,
        local: u32,
        output: u32,
        expiry_ms: u64,
    ) -> Self {
        let owner = owner.into();
        Self {
            key: escrow_claim_key(hasher, owner, intent, local, output, expiry_ms),
            intent,
            local,
            output,
            expiry_ms,
        }
    }

    /// Where the cell sits.
    #[must_use]
    pub const fn key(&self) -> SubstateKey {
        self.key
    }

    /// When it stops being owed.
    #[must_use]
    pub const fn expiry_ms(&self) -> u64 {
        self.expiry_ms
    }

    /// The record's value, once the execution knows what crossed and
    /// where it left from.
    #[must_use]
    pub const fn crossing(
        &self,
        resource: ResourceAddr,
        amount: u128,
        origin: SubstateKey,
    ) -> CrossingCell {
        CrossingCell {
            resource,
            amount,
            origin,
            intent: self.intent,
            local: self.local,
            output: self.output,
            expiry_ms: self.expiry_ms,
        }
    }

    /// Whether a record names the edge this site does.
    ///
    /// What a reclaim checks before crediting from a cell: the record's
    /// value re-derives its key, and a claim site built for one edge must
    /// not take a record written for another.
    #[must_use]
    pub fn names(&self, record: &CrossingCell) -> bool {
        record.intent == self.intent
            && record.local == self.local
            && record.output == self.output
            && record.expiry_ms == self.expiry_ms
    }

    /// The claim's value: which transaction took the crossing.
    #[must_use]
    pub const fn claimed_by(&self, tx: TxHash) -> ClaimCell {
        ClaimCell {
            tx,
            expiry_ms: self.expiry_ms,
        }
    }
}

/// When everything an intent's signature brought into being stops being
/// owed: the window its signer signed, plus the grace every
/// transaction-derived artifact gets.
///
/// One horizon for the nullifier and for the escrow cells of every node
/// the intent holds. The intent's own window rather than the
/// transaction's, for two reasons that are one: the transaction's window
/// is the intersection of every intent's, so this is never earlier than
/// it; and the transaction's window is the composer's to choose, where
/// an escrow key has to be made of nothing the composer chose.
#[must_use]
pub const fn intent_expiry_ms(header: &IntentHeader) -> u64 {
    header.validity_end_ms.saturating_add(NULLIFIER_GRACE_MS)
}

/// One admitted subintent: its signed identity, its signer, and the
/// nullifier key whose creation write makes it once-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubintentRecord {
    /// The signed declaration's hash.
    pub subintent: SubintentHash,
    /// The signer's account prefix.
    pub signer: PrincipalAddr,
    /// The canonical nullifier key under the signer.
    pub nullifier: SubstateKey,
    /// When the nullifier stops being owed — the subintent's own window
    /// end plus the grace. Carried beside the key because the cell's
    /// value states it and the key derives from it.
    pub expiry_ms: u64,
}

/// An admitted envelope tree: the flattened routing manifest with its
/// identity, plus the nullifier record of every bound subintent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedTree {
    /// The lowered manifest and the identity rooting fresh derivations.
    pub admitted: Admitted,
    /// One record per bound subintent, in envelope order.
    pub subintents: Vec<SubintentRecord>,
}

/// The tree's canonical bytes — what an envelope's body carries.
///
/// The vocabulary owns its own codec: a tree is an ordinary HBOR value,
/// and the encoding a composer writes is the one admission decodes.
///
/// # Panics
///
/// On a tree past the vocabulary's own caps — one no admission path can
/// have accepted.
#[must_use]
pub fn encode_tree(tree: &EnvelopeTree) -> Vec<u8> {
    to_vec(tree).expect("a tree within its caps encodes")
}

/// Admit a bound envelope tree: validate every intent, interleave the
/// tree into one flattened manifest over the sockets its intents
/// declare, and derive the subintent nullifier records.
///
/// `identity` is the signed envelope's hash — the root of every fresh
/// derivation. Distinct signed envelopes never mint the same fresh key,
/// even when they carry the same tree. `composer` is who signed the root
/// intent, and so whose identity the root's proof names; each subintent
/// names its own signer.
///
/// # Errors
///
/// Any [`AdmissionError`]; verdicts are deterministic and identical on
/// every node.
///
/// # Panics
///
/// Only on an index past `u32`, which the [`MAX_SUBINTENTS`] check above
/// it excludes.
pub fn admit_tree(
    tree: &EnvelopeTree,
    composer: PrincipalAddr,
    identity: ManifestHash,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
) -> Result<AdmittedTree, AdmissionError> {
    if tree.subintents.len() > MAX_SUBINTENTS {
        return Err(AdmissionError::TooManySubintents);
    }
    // Ahead of every subintent hash, for the reason `admit` checks ahead
    // of the graph hash.
    check_value_depth(&tree.root.graph)?;
    for subintent in &tree.subintents {
        check_value_depth(&subintent.decl.graph)?;
    }
    check_instance_value_depth(&tree.instances)?;
    let mut records = Vec::with_capacity(tree.subintents.len());
    let mut seen = BTreeSet::new();
    for (index, subintent) in tree.subintents.iter().enumerate() {
        let hash = subintent.decl.hash(hasher);
        if !seen.insert((subintent.signer, hash)) {
            return Err(AdmissionError::DuplicateSubintent {
                index: u32::try_from(index).expect("bounded by MAX_SUBINTENTS"),
            });
        }
        let expiry_ms = intent_expiry_ms(&subintent.decl.header);
        records.push(SubintentRecord {
            subintent: hash,
            signer: subintent.signer,
            nullifier: nullifier_key(hasher, subintent.signer, hash, expiry_ms),
            expiry_ms,
        });
    }

    let mut views = Vec::with_capacity(1 + tree.subintents.len());
    views.push(IntentView {
        graph: &tree.root.graph,
        sockets: &tree.root.sockets,
        bindings: &tree.root_bindings,
        signer: Some(composer),
        identity: tree.root.hash(hasher),
        expiry_ms: intent_expiry_ms(&tree.root.header),
    });
    for (subintent, record) in tree.subintents.iter().zip(&records) {
        views.push(IntentView {
            graph: &subintent.decl.graph,
            sockets: &subintent.decl.sockets,
            bindings: &subintent.bindings,
            signer: Some(subintent.signer),
            identity: record.subintent,
            expiry_ms: record.expiry_ms,
        });
    }
    // The envelope's own records, layered behind what the chain already
    // answers for. Each stands for the seal of the component it derives
    // and for nothing else — `Admission` holds every node targeting one to
    // being that component's seal.
    //
    // Which components the chain happens to hold does not enter it: an
    // envelope means the same thing wherever it is judged, so a record
    // beside an ordinary call is refused whether or not the component it
    // names is already there.
    let resolvable = Composed::new(chain, &tree.instances, hasher);
    let presented: BTreeSet<Address> = tree
        .instances
        .iter()
        .map(|meta| meta.address(hasher).address())
        .collect();
    let grants = PresentedGrants::from_presented(hasher, &tree.resources);
    let admitted = admit_intents(&views, identity, &resolvable, &presented, &grants, hasher)?;
    Ok(AdmittedTree {
        admitted,
        subintents: records,
    })
}

/// Route an admitted tree.
///
/// The flattened manifest's routing plus one exclusive nullifier
/// creation write per subintent at its signer's shard — the same union
/// effect set admission, scheduling, and execution all derive.
///
/// # Panics
///
/// Never: the only fallible insert folds reserve amounts, and a nullifier
/// is declared as an exclusive write.
#[must_use]
pub fn route_tree(tree: &AdmittedTree, shards: &dyn ShardResolver) -> Routing {
    let mut routing = route(&tree.admitted, shards);
    for record in &tree.subintents {
        let shard = shards.shard_of(record.signer.address());
        let effect = Effect {
            target: EffectTarget::Point(record.nullifier),
            mode: Mode::Write { moves: Moves::Both },
        };
        // No signature declared this, so it belongs to no frame.
        routing.push_kernel_effect(shard, effect);
    }
    routing
}
