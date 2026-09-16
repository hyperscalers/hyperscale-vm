//! The tree: intents composing intents through the interfaces they
//! declare, and the nullifier vocabulary that makes a committed intent
//! once-only.
//!
//! An intent's signer signs an [`Intent`] whole: its calls, the accounts
//! it acts as, the interface it presents — [`Socket`]s for what it needs
//! and [`Give`]s for the value it offers — and the members it composes,
//! each nested inside it with the wiring that fills its sockets. Two things
//! cross an intent boundary: a value edge, which exactly one node
//! argument consumes, and a claim, which as many of the intent's nodes
//! present as ask for it. Value flows both ways — a composer wires its
//! own edges and its members' gives into a member's sockets, and takes a
//! member's gives as arguments of its own calls — and authority flows
//! down only: a composer grants a claim it holds into a member's socket,
//! and nothing a member proves reaches its composer.
//!
//! An intent's hash covers every member's hash, and so the whole subtree
//! beneath it. That is what makes a grant safe: an account's claim is
//! wired into a member only by an intent that names the account or
//! received the claim in a socket of its own, and that intent signed the
//! member it grants to. Nothing about the tree is renegotiated at
//! admission.
//!
//! [`admit_tree`] walks the tree in preorder, resolves every socket and
//! every give to the node that fills it, and flattens the tree into one
//! routing manifest: intents keep tree order and their sockets interleave
//! them deterministically, so a node lands after whatever fills every
//! socket and every give it reaches. A tree admitting no such order is
//! rejected.
//!
//! Committing an intent writes a kernel nullifier substate under each
//! account it acts as, bucketed by the intent's expiry and keyed by its
//! own hash — computable, hence declarable, hence a creation conflict:
//! two trees racing one intent contend on the nullifier key and exactly
//! one commits.

use std::collections::BTreeSet;

use hyperscale_hbor::{
    DecodeError, Hbor, from_slice, from_slice_with_depth, to_vec, to_vec_with_depth,
};
use hyperscale_vm_types::{
    ARTIFACT_GRACE_MS, AccountSigner, Address, Attestation, COMMITTED_GRACE_MS, CROSSING_GRACE_MS,
    Effect, EffectTarget, IntentHash, LegShape, MAX_ATTESTATIONS, MAX_MANIFEST_NODES, Mode, Moves,
    NetworkId, PrincipalAddr, ResourceAddr, SubstateKey, SweepBucket, TxHash,
};
pub use hyperscale_vm_types::{MAX_INTENTS, attest};

use crate::PACKAGE_SLOT_BASE;
use crate::admission::{
    AdmissionError, Admitted, IntentView, MAX_SOCKETS, admit_intents, check_instance_value_depth,
    check_value_depth, flatten, resolve_tree,
};
use crate::claim::Claim;
use crate::dsl::PresentedGrants;
use crate::graph::{Constraint, EdgeRef, GiveRef, ManifestGraph};
use crate::hash::Hasher;
use crate::instance::InstanceMeta;
use crate::manifest::ManifestHash;
use crate::records::{ChainRecords, Composed};
use crate::resource::ResourceMeta;
use crate::types::{MAX_VALUE_WIRE_DEPTH, SlotId, bucketed_child_key, child_key};

/// The kernel-reserved role of intent nullifier substates under an
/// account's prefix.
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

/// The most bytes a [`Marker`] cell holds.
///
/// A nullifier, a committed cell or a claim, each a transaction hash,
/// an expiry and what it marks. The width the declaration prices these
/// cells at, held to by the encoding pin beside the type.
pub const MARKER_CELL_BYTES: u32 = 96;

/// The most bytes a [`CrossingCell`] holds: the escrow record under a
/// producing node's target, on [`MARKER_CELL_BYTES`]'s terms.
pub const CROSSING_CELL_BYTES: u32 = 256;

/// The bound on accounts one intent may act as. A wire bound, and
/// refused at admission for a tree built in memory.
///
/// Each account costs the intent one nullifier — a sweepable cell of
/// [`MARKER_CELL_BYTES`] under the account's prefix, counted against
/// the creation budget a block rations at five cells per transaction —
/// one read of the account's `auth` cell, and one sign-in condition its
/// own shard judges at materialization. Every one of those shards is
/// one the transaction's core must wait on, so an intent acting as many
/// accounts runs whole across all of them. Eight admits every shape a
/// party composes across its own accounts; past that an intent spends
/// two transactions' share of the block's sweepable budget on
/// nullifiers alone and holds a core across as many shards.
pub const MAX_ACCOUNTS: usize = 8;

/// The bound on how deep a tree nests: a root alone is one, and each
/// member sits one deeper than its composer.
///
/// Depth costs placement rather than correctness — every account of
/// every intent is judged on a shard the core waits on, and every node
/// presenting a granted claim is the core's, so a deep tree increasingly
/// runs whole — and it costs a nullifier per account per intent against
/// the sweepable budget. Eight admits a group assembled from groups a
/// few times over and holds the wire's nesting to a figure a decoder
/// walks without a stack of its own.
pub const MAX_TREE_DEPTH: usize = 8;

/// The codec nesting cost of the deepest admissible tree.
///
/// A tree at [`MAX_TREE_DEPTH`] carrying a literal at the value depth
/// bound costs exactly this many codec levels: six from the tree down
/// to a literal in one of the root's arguments beyond the literal's own,
/// and four per nested member — its list, the member, the signed intent
/// and the intent inside it. Pinned by test at both boundaries, and the
/// cap [`decode_tree`] decodes under, so a tree past the depth bound is
/// refused by the decoder before anything walks it.
pub const TREE_WIRE_DEPTH: usize = 6 + MAX_VALUE_WIRE_DEPTH + 4 * (MAX_TREE_DEPTH - 1);

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
/// itself, which the intent composing it fills.
///
/// Shaped, which is what the name is for: the declaration says what may
/// arrive, and wiring that does not fit is refused rather than accepted
/// and dealt with. Two things cross an intent boundary and both cross
/// this way — **the declaration says what**, and its signer signs that;
/// **the composer says whose**, in wiring the composer signs and the
/// declaring party never sees. That split is the whole of what makes an
/// intent composable without its signer having met the composer.
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
    /// nodes present through [`crate::EvidenceRef::Socket`] and which
    /// its own wiring may grant onward into a member's socket.
    ///
    /// The claim is the declaration's, so a holder signs *which
    /// authority they are asking for* and never who supplies it — and
    /// admission presents that claim alone, never whatever else its
    /// source carries, so a composer cannot smuggle authority into an
    /// intent its signer never offered.
    Authority(Claim),
}

/// One value edge an intent offers the intent composing it.
///
/// Value alone: there is no give that carries a claim, so authority has
/// no channel upward and no field in which to write the hazard. What a
/// composer may take from a member is exactly this list, by position —
/// never a node of the member's graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Give {
    /// An output of this intent's own graph that no node of it consumes.
    Edge(EdgeRef),
    /// A give of one of this intent's members, offered on: how a sealed
    /// group exposes a product assembled beneath it.
    Member(GiveRef),
}

/// The terms an intent is admissible under: the network it was declared
/// for and the window it stands in.
///
/// Its signer signs these with the rest of the declaration, so a
/// composer can neither retarget an intent nor outlive the window the
/// signer offered it for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct IntentHeader {
    /// The network this intent is declared for.
    ///
    /// Signed by the intent's own signer rather than inherited from the
    /// root, so a member binds only into a tree for the network its
    /// signer named.
    pub network: NetworkId,
    /// The window's inclusive start, in weighted-time milliseconds.
    ///
    /// Milliseconds rather than a range type: what a clock reading
    /// *means* is the workspace's, and this crate holds the number its
    /// signer signed.
    pub validity_start_ms: u64,
    /// The window's exclusive end.
    ///
    /// What ends the intent's admissibility, and so what ends the life
    /// of the nullifier that makes an intent once-only. A signer who
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

/// One signed intent: what one party wants, and what it composes.
///
/// Recursive. A leaf has no members; an intent with members composes
/// them, and every intent with members is a composer whatever its
/// depth. The root is the one nobody composes — it carries the terms
/// and declares no sockets, since nothing above it could fill one. Its
/// signer signs exactly this, so [`Intent::hash`] is the intent's
/// identity whatever tree later carries it, and since the hash covers
/// every member's the identity commits to the whole subtree.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Intent {
    /// What the intent is admissible under, as against what it does.
    ///
    /// Grouped rather than flat because these are the terms that bound
    /// the intent and the nullifier it spends, and because the preimage
    /// then covers the header whole — a term added here cannot go
    /// unsigned.
    pub header: IntentHeader,
    /// The accounts this intent acts as: each the owner of one of its
    /// nullifiers, each signed in on its own shard under its own stored
    /// rule against the keys that attest this intent, and each a claim
    /// the intent's own nodes present and its wiring may grant. Never
    /// empty. Inside the signed declaration, so the intent's own signer
    /// consents to which accounts it acts as.
    #[hbor(max = MAX_ACCOUNTS)]
    pub accounts: Vec<PrincipalAddr>,
    /// The principals whose keys attest this intent, in the order their
    /// attestations stand beside it. Never empty, never repeating.
    /// Inside the signed declaration, so one intent hash admits exactly
    /// one attesting set, and every account's shard judges its own rule
    /// against that set.
    #[hbor(max = MAX_ATTESTATIONS)]
    pub attested_by: Vec<PrincipalAddr>,
    /// The intent's invocation graph; arguments may reference the
    /// sockets via [`crate::GraphArg::Socket`] and the members' gives
    /// via [`crate::GraphArg::Give`].
    pub graph: ManifestGraph,
    /// The sockets this intent declares. A value socket is consumed by
    /// exactly one node argument or wired on to exactly one member's
    /// socket; an authority socket is presented by as many nodes, and
    /// granted on to as many members, as ask for it.
    #[hbor(max = MAX_SOCKETS)]
    pub sockets: Vec<Socket>,
    /// The value this intent offers its composer. Each is consumed
    /// exactly once above: by an argument of the composer's own graph,
    /// by the composer's wiring into a sibling's socket, or by the
    /// composer's own gives. Empty on the root, which has nobody to give
    /// to.
    #[hbor(max = MAX_SOCKETS)]
    pub gives: Vec<Give>,
    /// The intents this one composes, each with the wiring that fills
    /// its sockets. Nested rather than named: a composer contains its
    /// members, so which intent composes which is the shape of the
    /// value and not a relation admission has to recover.
    #[hbor(max = MAX_INTENTS)]
    pub members: Vec<Member>,
}

/// An intent and the attestations over it: what a counterparty hands
/// over, and what a composer places as a member.
///
/// Verifiable on its own before anybody composes it — each attestation
/// pairs by position with the principal the intent declares itself
/// attested by, and covers the intent's hash. The attestations are
/// transport: the intent's hash, and so the hash of any intent
/// composing it, covers the declared principals and never the
/// signature bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct SignedIntent {
    /// The declaration.
    pub intent: Intent,
    /// One attestation per principal in the intent's `attested_by`, in
    /// that order, each over the intent's hash.
    #[hbor(max = MAX_ATTESTATIONS)]
    pub signatures: Vec<Attestation>,
}

impl SignedIntent {
    /// `intent` with no attestation yet.
    #[must_use]
    pub const fn unsigned(intent: Intent) -> Self {
        Self {
            intent,
            signatures: Vec::new(),
        }
    }

    /// Attest the intent with `key`, standing the attestation beside
    /// those already given. The caller signs in the order the intent
    /// declares its attesting principals.
    pub fn attest<S: AccountSigner>(&mut self, key: &S, hasher: &dyn Hasher) {
        let hash = self.intent.hash(hasher);
        self.signatures.push(attest(key, &hash.0.0));
    }
}

/// One member of a composing intent: the signed intent, and how its
/// composer fills its sockets.
///
/// The wiring travels with the member it fills — one binding per socket
/// the member declares. Every source is the composer's own: its graph,
/// its members' gives, its own sockets and its own accounts, which is
/// what confines a grant to what the granting intent holds.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Member {
    /// The composed intent with its attestations, whole.
    pub signed: SignedIntent,
    /// One binding per socket the intent declares, in declaration order.
    #[hbor(max = MAX_SOCKETS)]
    pub wiring: Vec<Binding>,
}

const DOMAIN_INTENT: &[u8] = b"hyperscale-vm/intent";
const DOMAIN_INTENT_TREE: &[u8] = b"hyperscale-vm/envelope-tree";

impl Intent {
    /// The intent's identity through the hasher seam: the header, the
    /// accounts, the attesting principals, the graph hash, every socket,
    /// every give, and every member's hash with its wiring, each part
    /// carrying its canonical encoding. A member's attestations stay
    /// out: they are transport, and the principals they pair with are
    /// in the member's own hash.
    ///
    /// The fields are destructured rather than read one at a time, and
    /// the header enters whole through its own encoding, because
    /// everything else the declaration carries is content its signer
    /// signs. A field this preimage misses is a field in the format, in
    /// the encoding, and unsigned — so a new one either fails the build
    /// here or rides the header's encoding, and never passes silently.
    ///
    /// # Panics
    ///
    /// Hashed intents pass the depth gate first, as
    /// [`Value::canonical_bytes`](crate::types::Value::canonical_bytes)
    /// requires of the literals the graph hash feeds on.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> IntentHash {
        let Self {
            header,
            accounts,
            attested_by,
            graph,
            sockets,
            gives,
            members,
        } = self;
        let graph = graph.hash(hasher);
        let mut parts: Vec<Vec<u8>> =
            Vec::with_capacity(4 + sockets.len() + gives.len() + 2 * members.len());
        parts.push(to_vec(header).expect("a header is scalars"));
        parts.push(to_vec(accounts).expect("accounts are bounded addresses"));
        parts.push(to_vec(attested_by).expect("attesting principals are bounded addresses"));
        parts.push(graph.0.0.to_vec());
        for socket in sockets {
            parts.push(to_vec(socket).expect("a socket is shallow"));
        }
        for give in gives {
            parts.push(to_vec(give).expect("a give is two indices"));
        }
        for member in members {
            parts.push(member.signed.intent.hash(hasher).0.0.to_vec());
            parts.push(to_vec(&member.wiring).expect("wiring is bounded indices"));
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        IntentHash(hasher.hash(DOMAIN_INTENT, &refs))
    }

    /// How deep this intent nests: one for a leaf, one more than the
    /// deepest member otherwise.
    #[must_use]
    pub fn depth(&self) -> usize {
        1 + self
            .members
            .iter()
            .map(|member| member.signed.intent.depth())
            .max()
            .unwrap_or(0)
    }

    /// Every member's signed intent beneath this one, in tree order, for
    /// a verifier walking what each attestation covers.
    #[must_use]
    pub fn signed_members(&self) -> Vec<&SignedIntent> {
        let mut signed = Vec::new();
        let mut stack: Vec<&Member> = self.members.iter().rev().collect();
        while let Some(member) = stack.pop() {
            signed.push(&member.signed);
            stack.extend(member.signed.intent.members.iter().rev());
        }
        signed
    }

    /// Run `visit` over every member's signed intent beneath this one,
    /// each before its own members — how a fixture attests a tree it
    /// assembled unsigned.
    pub fn for_each_signed_member(&mut self, visit: &mut impl FnMut(&mut SignedIntent)) {
        for member in &mut self.members {
            visit(&mut member.signed);
            member.signed.intent.for_each_signed_member(visit);
        }
    }

    /// A leaf acting as `account` under `header`, attested by that
    /// account's own key: a graph, no interface, no members.
    #[must_use]
    pub fn leaf(header: IntentHeader, account: PrincipalAddr, graph: ManifestGraph) -> Self {
        Self {
            header,
            accounts: vec![account],
            attested_by: vec![account],
            graph,
            sockets: Vec::new(),
            gives: Vec::new(),
            members: Vec::new(),
        }
    }
}

/// What a composer puts in one of a member's sockets.
///
/// The composer's choice, signed by the composer and never by the
/// declaring member — which is what lets one signed intent be carried
/// by any composer that can fill its sockets. Every source is the
/// composer's own; a composer names nothing inside a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Binding {
    /// A value edge, for a value socket.
    Value(ValueSource),
    /// A claim, for an authority socket.
    Authority(ClaimSource),
}

/// Where a composer takes the value it wires into a member's socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum ValueSource {
    /// An output of the composer's own graph that no node of it
    /// consumes.
    Edge(EdgeRef),
    /// A give of one of the composer's members — a sibling's product,
    /// or the socket-owner's own, routed back to it.
    Give(GiveRef),
    /// One of the composer's own value sockets, wired straight through:
    /// how a sealed group presents a member's need as its own.
    Socket(u32),
}

/// What stands behind a claim a composer grants into a member's socket.
///
/// Three things in an intent can, and each is judged against what the
/// intent holds. A node proves what it read state to verify — a badge
/// in a vault, a component's own gate — and the claim is that node's
/// verdict. An account proves nothing and needs to: its shard attests
/// the keys that signed the intent, so the claim is the signature's, and
/// it stands before any node runs. A socket carries a claim the composer
/// itself received from above, granted on — how a claim reaches a
/// distant descendant, re-granted at every level by someone who signed
/// that level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum ClaimSource {
    /// The claim node `producer` of the composer's own graph proves.
    Node(u32),
    /// An account the composer acts as, granted by the signer who signed
    /// it.
    ///
    /// The account is stated here rather than read off the intent, so a
    /// grant says what it gives and admission judges the two against
    /// each other. Deriving it instead would make the field that decides
    /// whose authority this is one nobody wrote.
    Account(PrincipalAddr),
    /// One of the composer's own authority sockets, granted on.
    Socket(u32),
}

/// The tree an envelope carries and admission runs over: the root, with
/// every intent it composes nested inside it, and the creation-fixed
/// records their calls resolve against.
///
/// Tree order is preorder: the root first, then each member's subtree in
/// the order its composer holds it. Every flat reading of the tree — the
/// attesting sets, the nullifier records, the flattened manifest — is in
/// that order.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct IntentTree {
    /// The intent nobody composes, and beneath it every other intent the
    /// tree holds. Its attestations are the envelope's, since what they
    /// cover is the envelope: the root's hash, the terms and the
    /// artifact.
    pub root: Intent,
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

impl IntentTree {
    /// Every intent the tree holds, in tree order.
    #[must_use]
    pub fn intents(&self) -> Vec<&Intent> {
        let mut intents = Vec::new();
        let mut stack = vec![&self.root];
        while let Some(intent) = stack.pop() {
            intents.push(intent);
            stack.extend(
                intent
                    .members
                    .iter()
                    .rev()
                    .map(|member| &member.signed.intent),
            );
        }
        intents
    }

    /// A tree of one intent: a graph its own account signs, composing
    /// nobody.
    ///
    /// The shape every transaction that composes with nobody has, which
    /// is most of them.
    #[must_use]
    pub const fn of_one(root: Intent) -> Self {
        Self {
            root,
            instances: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// How many nodes the tree lowers to, over every intent it carries
    /// — the count of compute ceilings the root's terms sign.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.intents()
            .into_iter()
            .map(|intent| intent.graph.nodes.len())
            .sum()
    }

    /// The tree's own identity — the fallback for callers that sign
    /// nothing beyond the tree. A protocol envelope signing more derives
    /// its identity from the full signed form and passes that to
    /// [`admit_tree`] instead.
    ///
    /// The root's hash covers every intent beneath it, so what the tree
    /// adds is the records.
    ///
    /// # Panics
    ///
    /// Hashed trees pass the depth gate first, as
    /// [`Value::canonical_bytes`](crate::types::Value::canonical_bytes)
    /// requires of the literals the graph hashes feed on.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> ManifestHash {
        let parts: [Vec<u8>; 3] = [
            self.root.hash(hasher).0.0.to_vec(),
            // What the tree's calls resolve against is part of what was
            // composed, so two trees differing only here are two
            // identities.
            to_vec(&self.instances).expect("instance records are wire-bounded values"),
            to_vec(&self.resources).expect("resource records are wire-bounded values"),
        ];
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        ManifestHash(hasher.hash(DOMAIN_INTENT_TREE, &refs))
    }
}

/// The canonical nullifier key for a signed intent under one of its
/// accounts:
/// `account_prefix | expiry_bucket | H(nullifier_role, intent_hash,
/// expiry)`.
///
/// The expiry is part of the identity rather than only of the value, so
/// a spend cannot claim a life the declaration does not give it: the key
/// a false expiry names is not the key the screen expects, and the
/// declaration does not cover it.
///
/// It is in the identity twice over — hashed into the body and, coarsely,
/// leading the local half — so a nullifier answers *when* it stops being
/// needed from its key alone, and one account's nullifiers for one
/// bucket are a contiguous leaf-key range for a sweep to walk. Both halves come
/// from the one `expiry_ms` argument, so neither can drift from the
/// other.
#[must_use]
pub fn nullifier_key(
    hasher: &dyn Hasher,
    account: impl Into<Address>,
    intent: IntentHash,
    expiry_ms: u64,
) -> SubstateKey {
    bucketed_child_key(
        hasher,
        account,
        NULLIFIER_SLOT,
        SweepBucket::of(expiry_ms),
        &[intent.0.0.to_vec(), expiry_ms.to_le_bytes().to_vec()],
    )
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
    intent: IntentHash,
    local: u32,
    output: u32,
) -> SubstateKey {
    child_key(
        hasher,
        owner,
        ESCROW_RECORD_SLOT,
        &[
            intent.0.0.to_vec(),
            local.to_le_bytes().to_vec(),
            output.to_le_bytes().to_vec(),
        ],
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
    intent: IntentHash,
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
    intent: IntentHash,
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
/// left on, when it stops being claimable, and who issued it.
///
/// Self-describing on [`Marker`]'s terms: the value re-derives the
/// key, so a reader holding nothing but the leaf can tell what it is.
/// Unlike the sweepable families the key carries no bucket, so re-deriving
/// it is all a reader gets — a record is not sweepable and no expiry in
/// the key could make it so.
///
/// The edge is named here as well as in the key because a reclaim reads
/// this cell and nothing else — the producing shard credits the resource
/// and the amount back from the leaf alone, holding no transaction body
/// and no window of them. So is the cell the value left: a reclaim
/// credits it, and no rule the kernel could hold says which of an owner's
/// cells that is — an account's vault for a resource is the account
/// package's own layout, and a component's is another.
///
/// The expiry, the issuing transaction and the consumer's claim are
/// terms of the reclaim rather than the record's identity, which stays
/// the edge ([`CrossingSite::names`]). The transaction is what a
/// successor's reclaim is admitted under, the tick and its receipt being
/// keyed by transaction and a record naming none being unadmittable. The
/// consumer's claim is the cell that decides between the two housekeeping
/// members a record ends in: present says the crossing was taken and the
/// record is the retirement's, absent past the lapse says it was not and
/// the value is the producer's to credit back. Nothing else names it —
/// its owner is the consuming node's target, which lives in the manifest
/// and not in the leaf — so a holder of the record and no body could not
/// derive it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct CrossingCell {
    /// The resource that crossed.
    pub resource: ResourceAddr,
    /// How much of it.
    pub amount: u128,
    /// The signed intent the producing node belongs to.
    pub intent: IntentHash,
    /// That node's index within its own intent.
    pub local: u32,
    /// Which of its outputs the edge carried.
    pub output: u32,
    /// When no chain can still be claiming the crossing: the producing
    /// intent's own window end plus [`CROSSING_GRACE_MS`] — the intent's,
    /// not the transaction's, so the composer chooses no part of it.
    pub expiry_ms: u64,
    /// The transaction whose execution issued the crossing.
    pub tx: TxHash,
    /// The claim cell the consumer writes when it takes the crossing,
    /// under the consuming node's target. Retained by the shard holding
    /// that prefix until this record's `expiry_ms`, which is where a
    /// reader's window to judge it absent closes.
    pub consumer_claim: SubstateKey,
    /// The cell the value left, which a reclaim credits: the one cell of
    /// the producing frame denominated in the resource that crossed,
    /// resolved by the kernel at the issue. `None` where the frame holds
    /// no such cell or several, and the crossing is then nobody's to
    /// take back.
    pub origin: Option<SubstateKey>,
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

/// What a marker cell holds: which transaction wrote it, when it stops
/// being needed, and which family it belongs to.
///
/// Three families share this one value, and each is self-describing on
/// the same terms: the value re-derives the cell's own key under the
/// family's role, so a reader holding nothing but the leaf can tell a
/// marker from any other cell, tell which family it is, and tell whether
/// it is still owed. The key leads with the expiry's bucket, so a shard's
/// markers for one bucket are a contiguous range a sweep walks, and
/// [`Marker::key`] is the one derivation every writer and every reader
/// agree by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct Marker {
    /// The transaction that wrote it.
    pub tx: TxHash,
    /// When the marker stops being owed: its intent's validity end plus
    /// its family's own grace, on that family's own terms.
    pub expiry_ms: u64,
    /// The fact the marker records.
    pub marks: Marked,
}

/// The fact a marker records, and so the family it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Marked {
    /// An intent was spent, under one of its accounts' prefix
    /// ([`nullifier_key`]): what makes a committed intent once-only,
    /// and what a signer writes to cancel one.
    Spent(IntentHash),
    /// The shard committed the transaction, under the shard's own owner
    /// ([`committed_tx_key`]): what a leg proves absent to show its core
    /// never included the transaction.
    Committed,
    /// A crossing was taken, under the target of the node that took it
    /// ([`escrow_claim_key`]): what makes exactly one of the consumer's
    /// claim and the producer's reclaim happen.
    Claimed {
        /// The signed intent the producing node belongs to.
        intent: IntentHash,
        /// That node's index within its own intent.
        local: u32,
        /// Which of its outputs the edge carried.
        output: u32,
    },
}

impl Marked {
    /// When a cell of this family stops being owed, for one derived from
    /// a signed window ending at `validity_end_ms`.
    ///
    /// The one place the families' lives are stated, so a writer cannot
    /// give a cell a life its family does not have — the same discipline
    /// [`Marker::key`] enforces on the key, one level up. A grace each,
    /// because each answers a different reader over a different span,
    /// and the argument for every one of them is at its own constant.
    #[must_use]
    pub const fn expiry_ms(self, validity_end_ms: u64) -> u64 {
        validity_end_ms.saturating_add(match self {
            Self::Spent(_) => ARTIFACT_GRACE_MS,
            Self::Committed => COMMITTED_GRACE_MS,
            Self::Claimed { .. } => CROSSING_GRACE_MS,
        })
    }
}

impl Marker {
    /// The marker `marks` for `tx`, owed until its own family's grace
    /// past the signed window it was derived from.
    ///
    /// The expiry is derived rather than taken, so the family and the
    /// life it is written with cannot come apart.
    #[must_use]
    pub const fn of(tx: TxHash, validity_end_ms: u64, marks: Marked) -> Self {
        Self {
            tx,
            expiry_ms: marks.expiry_ms(validity_end_ms),
            marks,
        }
    }

    /// The cell this marker sits at under `owner`: the family's own key,
    /// re-derived from what the value says.
    #[must_use]
    pub fn key(&self, hasher: &dyn Hasher, owner: impl Into<Address>) -> SubstateKey {
        match self.marks {
            Marked::Spent(intent) => nullifier_key(hasher, owner, intent, self.expiry_ms),
            Marked::Committed => committed_tx_key(hasher, owner, self.tx, self.expiry_ms),
            Marked::Claimed {
                intent,
                local,
                output,
            } => escrow_claim_key(hasher, owner, intent, local, output, self.expiry_ms),
        }
    }

    /// The cell's committed bytes.
    ///
    /// The type owns its encoding, so the writer of one and a reader
    /// deciding what it is agree by construction rather than by two
    /// call sites staying in step.
    ///
    /// # Panics
    ///
    /// Never: the value is scalars.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("a marker is scalars")
    }

    /// A marker read back off the leaf, or nothing for bytes that are
    /// not one.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        from_slice(bytes).ok()
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
    intent: IntentHash,
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
        intent: IntentHash,
        local: u32,
        output: u32,
        expiry_ms: u64,
    ) -> Self {
        let owner = owner.into();
        Self {
            key: escrow_record_key(hasher, owner, intent, local, output),
            intent,
            local,
            output,
            expiry_ms,
        }
    }

    /// The record cell of the edge `producer` leaves on `output`: under
    /// its target, keyed by what its own signer signed.
    #[must_use]
    pub fn record_of(hasher: &dyn Hasher, producer: &LegShape, output: u32) -> Self {
        Self::record(
            hasher,
            producer.target,
            producer.intent,
            producer.local,
            output,
            producer.expiry_ms,
        )
    }

    /// The claim cell for the edge `producer` leaves on `output`, under
    /// `owner`: the consuming node's target for a consumer's claim, the
    /// producer's own for a reclaim's.
    #[must_use]
    pub fn claim_of(
        hasher: &dyn Hasher,
        owner: impl Into<Address>,
        producer: &LegShape,
        output: u32,
    ) -> Self {
        Self::claim(
            hasher,
            owner,
            producer.intent,
            producer.local,
            output,
            producer.expiry_ms,
        )
    }

    /// The claim cell for the edge `record` holds, under `owner`: the
    /// producer's own target for a settlement composed from the leaf,
    /// which holds no manifest to read the edge off.
    #[must_use]
    pub fn claim_on(hasher: &dyn Hasher, owner: impl Into<Address>, record: &CrossingCell) -> Self {
        Self::claim(
            hasher,
            owner,
            record.intent,
            record.local,
            record.output,
            record.expiry_ms,
        )
    }

    /// The claim cell for that edge, under the target of whatever takes
    /// it.
    #[must_use]
    pub fn claim(
        hasher: &dyn Hasher,
        owner: impl Into<Address>,
        intent: IntentHash,
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
    /// which transaction issued it.
    #[must_use]
    pub const fn crossing(
        &self,
        tx: TxHash,
        resource: ResourceAddr,
        amount: u128,
        consumer_claim: SubstateKey,
        origin: Option<SubstateKey>,
    ) -> CrossingCell {
        CrossingCell {
            resource,
            amount,
            intent: self.intent,
            local: self.local,
            output: self.output,
            expiry_ms: self.expiry_ms,
            tx,
            consumer_claim,
            origin,
        }
    }

    /// Whether a record names the edge this site does.
    ///
    /// What a reclaim checks before crediting from a cell: the record's
    /// value re-derives its key, and a claim site built for one edge must
    /// not take a record written for another.
    #[must_use]
    pub fn names(&self, record: &CrossingCell) -> bool {
        record.intent == self.intent && record.local == self.local && record.output == self.output
    }

    /// The claim's value: which transaction took the crossing, on this
    /// edge.
    #[must_use]
    pub const fn claimed_by(&self, tx: TxHash) -> Marker {
        Marker {
            tx,
            expiry_ms: self.expiry_ms,
            marks: Marked::Claimed {
                intent: self.intent,
                local: self.local,
                output: self.output,
            },
        }
    }
}

/// When an intent's nullifier stops being owed: the window its signer
/// signed, plus the grace [`Marked::Spent`] takes.
///
/// The intent's own window rather than the transaction's, for two
/// reasons that are one: the transaction's window is the intersection
/// of every intent's, so this is never earlier than it; and the
/// transaction's window is the composer's to choose, where a key has to
/// be made of nothing the composer chose.
#[must_use]
pub const fn nullifier_expiry_ms(header: &IntentHeader) -> u64 {
    header.validity_end_ms.saturating_add(ARTIFACT_GRACE_MS)
}

/// When the escrow cells of every node an intent holds stop being owed:
/// the window its signer signed, plus the grace [`Marked::Claimed`]
/// takes.
///
/// The intent's own window, on [`nullifier_expiry_ms`]'s terms and for
/// the same two reasons. The grace differs because the families do: a
/// nullifier is answered on its own chain, and a crossing is decided
/// across a reshape cut.
#[must_use]
pub const fn crossing_expiry_ms(header: &IntentHeader) -> u64 {
    header.validity_end_ms.saturating_add(CROSSING_GRACE_MS)
}

/// One nullifier an admitted intent writes: under which account, and
/// at which cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nullifier {
    /// The account the intent acts as, whose prefix the cell sits under.
    pub account: PrincipalAddr,
    /// The canonical nullifier key under that account.
    pub key: SubstateKey,
}

/// One admitted intent: its signed identity and the nullifier keys
/// whose creation writes make it once-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentRecord {
    /// The signed intent's hash.
    pub intent: IntentHash,
    /// One nullifier per account the intent acts as, in the order the
    /// intent names them.
    pub nullifiers: Vec<Nullifier>,
    /// When the nullifiers stop being owed — the intent's own window
    /// end plus the grace. Carried beside the keys because the cell's
    /// value states it and the key derives from it.
    pub expiry_ms: u64,
}

impl IntentRecord {
    /// The accounts the intent acts as, in the order it names them.
    pub fn accounts(&self) -> impl Iterator<Item = PrincipalAddr> + '_ {
        self.nullifiers.iter().map(|nullifier| nullifier.account)
    }
}

/// The tree's canonical bytes — what an envelope carries.
///
/// The vocabulary owns its own codec: a tree is an ordinary HBOR value
/// under [`TREE_WIRE_DEPTH`], and the encoding a composer writes is the
/// one [`decode_tree`] reads.
///
/// # Panics
///
/// On a tree past the vocabulary's own caps — one no admission path can
/// have accepted.
#[must_use]
pub fn encode_tree(tree: &IntentTree) -> Vec<u8> {
    to_vec_with_depth(tree, TREE_WIRE_DEPTH).expect("a tree within its caps encodes")
}

/// A tree read back off the bytes an envelope carries, under
/// [`TREE_WIRE_DEPTH`].
///
/// # Errors
///
/// [`DecodeError`] for bytes that are not a tree, or one nested past
/// the depth the vocabulary admits.
pub fn decode_tree(bytes: &[u8]) -> Result<IntentTree, DecodeError> {
    from_slice_with_depth(bytes, TREE_WIRE_DEPTH)
}

/// Admit a tree.
///
/// Validates every intent, resolves every interface to the nodes that
/// fill it, interleaves the tree into one flattened manifest, and
/// derives the nullifier records.
///
/// `identity` is the signed envelope's hash — the root of every fresh
/// derivation. Distinct signed envelopes never mint the same fresh key,
/// even when they carry the same tree. The principals whose keys attest
/// each intent, and the accounts it acts as, are the intent's own.
///
/// # Errors
///
/// Any [`AdmissionError`]; verdicts are deterministic and identical on
/// every node.
///
/// # Panics
///
/// Only on an index past `u32`, which the [`MAX_INTENTS`] check above it
/// excludes.
pub fn admit_tree(
    tree: &IntentTree,
    identity: ManifestHash,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    let flat = flatten(&tree.root)?;
    let intents = flat.intents();
    if intents.len() > MAX_INTENTS {
        return Err(AdmissionError::TooManyIntents);
    }
    // Ahead of every intent hash: hashing takes the depth bound as
    // given.
    for intent in intents {
        check_value_depth(&intent.graph)?;
    }
    check_instance_value_depth(&tree.instances)?;
    // The intent hash alone. It is what names every escrow record and
    // claim the tree derives — so two intents that hash alike derive one
    // key for two edges.
    let mut seen = BTreeSet::new();
    let mut identities = Vec::with_capacity(intents.len());
    for (index, intent) in intents.iter().enumerate() {
        let hash = intent.hash(hasher);
        if !seen.insert(hash) {
            return Err(AdmissionError::DuplicateIntent {
                index: u32::try_from(index).expect("bounded by MAX_INTENTS"),
            });
        }
        identities.push(hash);
    }
    let resolved = resolve_tree(&flat)?;
    let records: Vec<IntentRecord> = intents
        .iter()
        .zip(&identities)
        .map(|(intent, hash)| {
            let expiry_ms = nullifier_expiry_ms(&intent.header);
            IntentRecord {
                intent: *hash,
                nullifiers: intent
                    .accounts
                    .iter()
                    .map(|account| Nullifier {
                        account: *account,
                        key: nullifier_key(hasher, *account, *hash, expiry_ms),
                    })
                    .collect(),
                expiry_ms,
            }
        })
        .collect();

    let views: Vec<IntentView<'_>> = intents
        .iter()
        .zip(&records)
        .zip(resolved.views())
        .map(|((intent, record), interface)| IntentView {
            graph: &intent.graph,
            sockets: &intent.sockets,
            interface,
            accounts: &intent.accounts,
            attested_by: &intent.attested_by,
            identity: record.intent,
            expiry_ms: crossing_expiry_ms(&intent.header),
        })
        .collect();
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
    let mut admitted = admit_intents(&views, identity, &resolvable, &presented, &grants, hasher)?;
    // One exclusive nullifier creation per account per intent. No
    // signature declared these, so they belong to no frame — but they
    // are the once-only execution guarantee, so they are folded into the
    // declaration here rather than by a later pass.
    for nullifier in records.iter().flat_map(|record| &record.nullifiers) {
        admitted.push_kernel_effect(Effect {
            target: EffectTarget::Point(nullifier.key),
            mode: Mode::Write { moves: Moves::Both },
        });
    }
    Ok(admitted.with_intents(records))
}
