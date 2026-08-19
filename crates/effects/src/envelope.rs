//! The bound envelope tree: a root intent composed with separately
//! signed subintents over typed yield edges, and the nullifier
//! vocabulary that makes a committed subintent once-only.
//!
//! A subintent's signer signs an [`IntentDecl`] — a graph over declared
//! yield parameters, each a typed hole for a value edge the composition
//! supplies. The composer binds every hole to another intent's output
//! edge and signs the whole envelope; nothing about the tree is
//! renegotiated at admission. [`admit_tree`] flattens the tree into one
//! routing manifest: intents keep their author order, yield edges
//! interleave them deterministically, and a composition whose yields
//! admit no execution order is rejected — acyclicity is judged at yield
//! granularity.
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
    Address, Effect, EffectTarget, Mode, Presence, PrincipalAddr, ResourceRef, SubstateKey,
};

use crate::PACKAGE_SLOT_BASE;
use crate::admission::{
    AdmissionError, Admitted, IntentView, MAX_YIELD_PARAMS, admit_intents, check_instance_values,
    check_value_depth,
};
use crate::graph::{Constraint, EdgeRef, ManifestGraph};
use crate::hash::{Hash32, Hasher};
use crate::instance::{InstanceMeta, InstanceRegistry};
use crate::manifest::ManifestHash;
use crate::metadata::MetadataCache;
use crate::route::{MAX_MANIFEST_NODES, Routing, ShardResolver, route};
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

/// A typed inbound yield edge an intent declares: the composition must
/// bind an edge carrying exactly this resource, under the declaring
/// intent's own constraints.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct YieldParam {
    /// The resource the yielded edge must carry.
    pub resource: ResourceRef,
    /// The declaring intent's constraints on the yielded edge — the same
    /// language that constrains ordinary graph edges.
    pub constraints: Vec<Constraint>,
}

/// One intent's declared form: a graph over typed yield parameters.
///
/// The root intent and every subintent share this shape; a subintent's
/// signer signs exactly this, so [`IntentDecl::hash`] is the subintent's
/// identity whatever composition later carries it. Outputs the graph
/// does not consume internally are the intent's yields — the composition
/// must consume every one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct IntentDecl {
    /// The intent's invocation graph; arguments may reference the
    /// declared parameters via [`GraphArg::Param`].
    pub graph: ManifestGraph,
    /// The declared yield parameters, each consumed by exactly one node
    /// argument.
    #[hbor(max = MAX_YIELD_PARAMS)]
    pub params: Vec<YieldParam>,
}

/// A signed subintent's identity: the hash of its declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct SubintentHash(pub Hash32);

const DOMAIN_SUBINTENT: &[u8] = b"hyperscale-vm/subintent";
const DOMAIN_ENVELOPE_TREE: &[u8] = b"hyperscale-vm/envelope-tree";

impl IntentDecl {
    /// The declaration's identity through the hasher seam: the graph
    /// hash plus every declared parameter with its constraints, each
    /// parameter one part carrying its canonical encoding.
    ///
    /// # Panics
    ///
    /// Hashed declarations pass the depth gate first, as
    /// [`Value::canonical_bytes`](crate::types::Value::canonical_bytes)
    /// requires of the literals the graph hash feeds on.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> SubintentHash {
        let graph = self.graph.hash(hasher);
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(1 + self.params.len());
        parts.push(graph.0.0.to_vec());
        for param in &self.params {
            parts.push(to_vec(param).expect("a yield parameter is shallow"));
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        SubintentHash(hasher.hash(DOMAIN_SUBINTENT, &refs))
    }
}

/// One typed yield edge: the `output`-th edge of node `producer` inside
/// intent `intent`, bound to a declared parameter of the consuming
/// intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct YieldBinding {
    /// The producing intent: `0` names the root, `i + 1` names
    /// subintent `i`.
    pub intent: u32,
    /// The produced edge within that intent's graph.
    pub edge: EdgeRef,
}

/// A subintent bound into an envelope.
///
/// Carries the signed declaration, the signer's account prefix, and one
/// yield binding per declared parameter. The bindings are the
/// composer's choice and are covered by the envelope identity, never by
/// the subintent's own hash.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Subintent {
    /// What the subintent's signer signed.
    pub decl: IntentDecl,
    /// The signer's account prefix — the owner of the nullifier.
    pub signer: PrincipalAddr,
    /// The composition's binding for each declared parameter.
    #[hbor(max = MAX_YIELD_PARAMS)]
    pub bindings: Vec<YieldBinding>,
}

/// The bound envelope tree admission runs over: the composer's root
/// intent plus every bound subintent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct EnvelopeTree {
    /// The composer's own intent.
    pub root: IntentDecl,
    /// The composition's binding for each root parameter.
    #[hbor(max = MAX_YIELD_PARAMS)]
    pub root_bindings: Vec<YieldBinding>,
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
/// tree into one flattened manifest along its yield edges, and derive
/// the subintent nullifier records.
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
    cache: &MetadataCache,
    instances: &InstanceRegistry,
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
        params: &tree.root.params,
        bindings: &tree.root_bindings,
        signer: Some(composer.address()),
    });
    for subintent in &tree.subintents {
        views.push(IntentView {
            graph: &subintent.decl.graph,
            params: &subintent.decl.params,
            bindings: &subintent.bindings,
            signer: Some(subintent.signer.address()),
        });
    }
    let admitted = admit_intents(&views, identity, cache, instances, hasher)?;
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
            mode: Mode::Write {
                requires: Presence::Either,
            },
        };
        // No signature declared this, so it belongs to no frame.
        routing.push_kernel_effect(shard, effect);
    }
    routing
}
