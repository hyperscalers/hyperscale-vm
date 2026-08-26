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

use hyperscale_hbor::{Hbor, to_vec};
pub use hyperscale_vm_types::MAX_SUBINTENTS;
use hyperscale_vm_types::{
    Address, Effect, EffectTarget, MAX_MANIFEST_NODES, Mode, Moves, PrincipalAddr, ResourceAddr,
    SubstateKey,
};

use crate::PACKAGE_SLOT_BASE;
use crate::admission::{
    AdmissionError, Admitted, IntentView, MAX_SOCKETS, admit_intents, check_instance_values,
    check_value_depth,
};
use crate::claim::Claim;
use crate::dsl::PresentedGrants;
use crate::graph::{Constraint, EdgeRef, ManifestGraph};
use crate::hash::{Hash32, Hasher};
use crate::instance::InstanceMeta;
use crate::manifest::ManifestHash;
use crate::records::{ChainRecords, Composed};
use crate::resource::ResourceMeta;
use crate::route::{Routing, ShardResolver, route};
use crate::types::{SlotId, child_key};

/// The kernel-reserved role of subintent nullifier substates under a
/// signer's prefix.
///
/// The top of the role space is the kernel's, as the bottom is the
/// protocol vocabulary's and the middle is where packages number from.
pub const NULLIFIER_SLOT: SlotId = SlotId(0xFFFF);

// Held at compile time rather than by a test: both sides are constants,
// so a nullifier colliding with a package's own cell is a thing the
// build can refuse outright.
const _: () = assert!(NULLIFIER_SLOT.0 > PACKAGE_SLOT_BASE);

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
    /// nodes present through [`EvidenceRef::Socket`].
    ///
    /// The claim is the declaration's, so a holder signs *which
    /// authority they are asking for* and never who supplies it — and
    /// admission presents that claim alone, never whatever else the
    /// minting node happened to mint, so a composition cannot smuggle
    /// authority into an intent its signer never offered.
    Authority(Claim),
}

/// One intent's declared form: a graph over typed sockets.
///
/// The root intent and every subintent share this shape; a subintent's
/// signer signs exactly this, so [`IntentDecl::hash`] is the subintent's
/// identity whatever composition later carries it. Outputs the graph
/// does not consume internally are the intent's yields — the composition
/// must bind every one to some intent's socket.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct IntentDecl {
    /// The intent's invocation graph; arguments may reference the
    /// sockets via [`GraphArg::Socket`].
    pub graph: ManifestGraph,
    /// The sockets this intent declares. A value socket is consumed by
    /// exactly one node argument; an authority socket is presented by as
    /// many nodes as ask for it.
    #[hbor(max = MAX_SOCKETS)]
    pub sockets: Vec<Socket>,
}

/// A signed subintent's identity: the hash of its declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct SubintentHash(pub Hash32);

const DOMAIN_SUBINTENT: &[u8] = b"hyperscale-vm/subintent";
const DOMAIN_ENVELOPE_TREE: &[u8] = b"hyperscale-vm/envelope-tree";

impl IntentDecl {
    /// The declaration's identity through the hasher seam: the graph
    /// hash plus every socket it declares, each one part carrying its
    /// canonical encoding.
    ///
    /// # Panics
    ///
    /// Hashed declarations pass the depth gate first, as
    /// [`Value::canonical_bytes`](crate::types::Value::canonical_bytes)
    /// requires of the literals the graph hash feeds on.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> SubintentHash {
        let graph = self.graph.hash(hasher);
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(1 + self.sockets.len());
        parts.push(graph.0.0.to_vec());
        for socket in &self.sockets {
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
    /// The claim node `producer` of `intent` mints.
    Authority {
        /// The producing intent, numbered as above.
        intent: u32,
        /// The minting node within that intent's graph.
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
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
/// `signer_prefix | H(nullifier_role, subintent_hash)`.
#[must_use]
pub fn nullifier_key(
    hasher: &dyn Hasher,
    signer: impl Into<Address>,
    subintent: SubintentHash,
) -> SubstateKey {
    child_key(hasher, signer, NULLIFIER_SLOT, &[subintent.0.0.to_vec()])
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
    check_instance_values(&tree.instances)?;
    let mut records = Vec::with_capacity(tree.subintents.len());
    let mut seen = BTreeSet::new();
    for (index, subintent) in tree.subintents.iter().enumerate() {
        let hash = subintent.decl.hash(hasher);
        if !seen.insert((subintent.signer, hash)) {
            return Err(AdmissionError::DuplicateSubintent {
                index: u32::try_from(index).expect("bounded by MAX_SUBINTENTS"),
            });
        }
        records.push(SubintentRecord {
            subintent: hash,
            signer: subintent.signer,
            nullifier: nullifier_key(hasher, subintent.signer, hash),
        });
    }

    let mut views = Vec::with_capacity(1 + tree.subintents.len());
    views.push(IntentView {
        graph: &tree.root.graph,
        sockets: &tree.root.sockets,
        bindings: &tree.root_bindings,
        signer: Some(composer),
    });
    for subintent in &tree.subintents {
        views.push(IntentView {
            graph: &subintent.decl.graph,
            sockets: &subintent.decl.sockets,
            bindings: &subintent.bindings,
            signer: Some(subintent.signer),
        });
    }
    // The envelope's own records, layered behind what the chain already
    // answers for. Each stands for the seal of the component it derives
    // and for nothing else — `Lower` holds every node targeting one to
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
