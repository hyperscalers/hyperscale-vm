//! The tree: intents composing intents through the interfaces they
//! declare, and the nullifier vocabulary that makes a committed intent
//! once-only.
//!
//! An intent's signer signs an [`Intent`] whole: its calls, the accounts
//! it acts as, the interface it presents — [`Socket`]s for what it needs
//! and gives for the value it offers — and the members it composes,
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

use hyperscale_hbor::{DecodeError, Hbor, from_slice_with_depth, to_vec, to_vec_with_depth};
use hyperscale_vm_types::{
    AccountSigner, Address, Attestation, Effect, EffectTarget, IntentHash, MAX_ATTESTATIONS,
    MAX_MANIFEST_NODES, Mode, Moves, NetworkId, PrincipalAddr, ResourceAddr, SubstateKey,
};
pub use hyperscale_vm_types::{MAX_INTENTS, attest};

use crate::admission::{
    AdmissionError, Admitted, IntentView, MAX_SOCKETS, Wired, admit_intents,
    check_instance_value_depth, check_value_depth, flatten, resolve_tree, walk,
};
use crate::cells::{crossing_expiry_ms, nullifier_expiry_ms, nullifier_key};
use crate::claim::Claim;
use crate::dsl::PresentedGrants;
use crate::graph::{ClaimRef, Constraint, ManifestGraph, ValueRef};
use crate::hash::Hasher;
use crate::instance::InstanceMeta;
use crate::manifest::ManifestHash;
use crate::records::{ChainRecords, Composed};
use crate::resource::ResourceMeta;
use crate::types::MAX_VALUE_WIRE_DEPTH;

/// The bound on accounts one intent may act as. A wire bound, and
/// refused at admission for a tree built in memory.
///
/// Each account costs the intent one nullifier — a sweepable cell of
/// [`MARKER_CELL_BYTES`](crate::MARKER_CELL_BYTES) under the account's
/// prefix, counted against
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
    /// nodes present through [`ClaimRef::Socket`] and which
    /// its own wiring may grant onward into a member's socket.
    ///
    /// The claim is the declaration's, so a holder signs *which
    /// authority they are asking for* and never who supplies it — and
    /// admission presents that claim alone, never whatever else its
    /// source carries, so a composer cannot smuggle authority into an
    /// intent its signer never offered.
    Authority(Claim),
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
    /// The intent's invocation graph; its arguments may consume the
    /// sockets and the members' gives as [`ValueRef`]s beside its own
    /// edges.
    pub graph: ManifestGraph,
    /// The sockets this intent declares. A value socket is consumed by
    /// exactly one node argument or wired on to exactly one member's
    /// socket; an authority socket is presented by as many nodes, and
    /// granted on to as many members, as ask for it.
    #[hbor(max = MAX_SOCKETS)]
    pub sockets: Vec<Socket>,
    /// The value this intent offers its composer: an output of its own
    /// graph that no node of it consumes, or a give of one of its
    /// members offered on — how a sealed group exposes a product
    /// assembled beneath it. Never one of its own sockets, which would
    /// route the composer's value back to it. Each is consumed exactly
    /// once above: by an argument of the composer's own graph, by the
    /// composer's wiring into a sibling's socket, or by the composer's
    /// own gives. Empty on the root, which has nobody to give to.
    #[hbor(max = MAX_SOCKETS)]
    pub gives: Vec<ValueRef>,
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

impl From<Intent> for SignedIntent {
    /// The intent with no attestation yet.
    fn from(intent: Intent) -> Self {
        Self::unsigned(intent)
    }
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
    pub fn attest<S: AccountSigner + ?Sized>(&mut self, key: &S, hasher: &dyn Hasher) {
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
const DOMAIN_INTENT_TREE: &[u8] = b"hyperscale-vm/intent-tree";

impl Intent {
    /// The intent's identity through the hasher seam: the header, the
    /// accounts, the attesting principals, the graph hash, then the
    /// sockets, the gives, and every member's hash with its wiring, each
    /// section led by its count and each part carrying its canonical
    /// encoding. A member's attestations stay out: they are transport,
    /// and the principals they pair with are in the member's own hash.
    ///
    /// The counts are what make the section boundaries part of the
    /// preimage. The hasher frames each part, so the part sequence is
    /// injective; where one section ends and the next begins would
    /// otherwise be recoverable only from the parts' widths, which a
    /// narrower socket or address encoding could make ambiguous.
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
        let members: Vec<IntentHash> = self
            .members
            .iter()
            .map(|member| member.signed.intent.hash(hasher))
            .collect();
        self.hash_over(&members, hasher)
    }

    /// [`Intent::hash`] with the members' hashes supplied — one per
    /// member, in order — for a walk that hashes a tree bottom-up and
    /// computes each intent's hash once.
    ///
    /// # Panics
    ///
    /// As [`Intent::hash`], and on a count that is not the members'.
    #[must_use]
    pub fn hash_over(&self, members: &[IntentHash], hasher: &dyn Hasher) -> IntentHash {
        let Self {
            header,
            accounts,
            attested_by,
            graph,
            sockets,
            gives,
            members: composed,
        } = self;
        assert_eq!(
            members.len(),
            composed.len(),
            "one hash per member, in the composer's order"
        );
        let graph = graph.hash(hasher);
        let count = |len: usize| {
            u32::try_from(len)
                .expect("every section is wire-bounded")
                .to_le_bytes()
                .to_vec()
        };
        let mut parts: Vec<Vec<u8>> =
            Vec::with_capacity(7 + sockets.len() + gives.len() + 2 * composed.len());
        parts.push(to_vec(header).expect("a header is scalars"));
        parts.push(to_vec(accounts).expect("accounts are bounded addresses"));
        parts.push(to_vec(attested_by).expect("attesting principals are bounded addresses"));
        parts.push(graph.0.0.to_vec());
        parts.push(count(sockets.len()));
        for socket in sockets {
            parts.push(to_vec(socket).expect("a socket is shallow"));
        }
        parts.push(count(gives.len()));
        for give in gives {
            parts.push(to_vec(give).expect("a give is two indices"));
        }
        parts.push(count(composed.len()));
        for (member, hash) in composed.iter().zip(members) {
            parts.push(hash.0.0.to_vec());
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
/// composer's own — its graph's edges, its members' gives, its own
/// sockets passed through, and the claims it holds: a node's verdict,
/// an account it acts as, or a socket of its own granted on. A composer
/// names nothing inside a member, and a grant of a claim the composer
/// does not hold is refused where the wiring is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Binding {
    /// A value edge, for a value socket.
    Value(ValueRef),
    /// A claim, for an authority socket. An account is judged against
    /// the composer's `accounts`, a socket against the claim the
    /// composer's own socket carries.
    Authority(ClaimRef),
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

    /// Hold the tree to its shape: everything [`flatten`] holds a tree
    /// to, and the value depth of every literal and presented record —
    /// what has to be true before anything hashes or walks it.
    ///
    /// # Errors
    ///
    /// Any [`AdmissionError`] the shape earns.
    pub fn check_shape(&self) -> Result<(), AdmissionError> {
        let flat = flatten(&self.root)?;
        for intent in flat.intents() {
            check_value_depth(&intent.graph)?;
        }
        check_instance_value_depth(&self.instances)
    }

    /// Every intent's hash, in tree order, each computed once.
    ///
    /// [`Intent::hash`] recomputes the subtree beneath every member it
    /// covers; this walks the tree bottom-up instead, so a tree of `n`
    /// intents costs `n` hashes rather than one per ancestor of each.
    #[must_use]
    pub fn hashes(&self, hasher: &dyn Hasher) -> Vec<IntentHash> {
        walk(&self.root).hashes(hasher)
    }

    /// How many nodes the tree lowers to, over every intent it carries
    /// — the count of compute ceilings the envelope's terms sign.
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

/// Why bytes are not a tree admission could run over.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TreeDecodeError {
    /// Not a tree, or one nested past the depth the vocabulary admits.
    #[error("tree decode: {0}")]
    Decode(#[from] DecodeError),
    /// A tree, and one past the shape admission holds a tree to.
    #[error("tree shape: {0}")]
    Shape(#[from] AdmissionError),
}

/// A tree read back off the bytes an envelope carries, under
/// [`TREE_WIRE_DEPTH`], and held to its shape before it is returned.
///
/// The shape is the intent, depth and node caps, every intent's
/// accounts and attesting set, and every member's wiring arity.
/// Everything that walks a decoded tree — the hashing, the target
/// lookups, admission — runs over a tree inside its caps, and nothing a
/// stranger sends costs more than one bounded walk before it is refused.
///
/// # Errors
///
/// [`TreeDecodeError`] for bytes that are not a tree, or a tree past
/// its shape.
pub fn decode_tree(bytes: &[u8]) -> Result<IntentTree, TreeDecodeError> {
    let tree: IntentTree = from_slice_with_depth(bytes, TREE_WIRE_DEPTH)?;
    tree.check_shape()?;
    Ok(tree)
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
/// Only on an index past `u32`, which the [`MAX_INTENTS`] check in the
/// tree's shape excludes.
pub fn admit_tree(
    tree: &IntentTree,
    identity: ManifestHash,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    let flat = flatten(&tree.root)?;
    let intents = flat.intents();
    // Ahead of every intent hash: hashing takes the depth bound as
    // given.
    for intent in intents {
        check_value_depth(&intent.graph)?;
    }
    check_instance_value_depth(&tree.instances)?;
    // The intent hash alone. It is what names every escrow record and
    // claim the tree derives — so two intents that hash alike derive one
    // key for two edges.
    let identities = flat.hashes(hasher);
    let mut seen = BTreeSet::new();
    for (index, hash) in identities.iter().enumerate() {
        if !seen.insert(*hash) {
            return Err(AdmissionError::DuplicateIntent {
                index: u32::try_from(index).expect("bounded by MAX_INTENTS"),
            });
        }
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
        .zip(resolved.resolutions())
        .map(|((intent, record), resolution)| IntentView {
            wired: Wired {
                graph: &intent.graph,
                sockets: &intent.sockets,
                resolution,
            },
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
