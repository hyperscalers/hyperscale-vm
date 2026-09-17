//! Admission: the judgement that turns a signed form into a routing
//! manifest.
//!
//! One checker serves every tree. A leaf is the degenerate tree — one
//! intent with no members — and a composition is an intent nesting
//! members whose sockets its wiring fills, each carrying a value edge
//! or a proof. So [`admit_intents`]
//! takes a slice of [`IntentView`] and everything below it is
//! shape-agnostic: bindings and socket consumption per intent, a
//! deterministic interleave over the sockets each node names, then one
//! pass over the flattened node order checking arity, kinds, linearity,
//! and constraints.
//!
//! Nothing here reads state. Verdicts are a pure function of the signed
//! form and content-addressed metadata, which is what lets every node
//! reach the identical one.
//!
//! What stays here is the orchestration: the checks in order, and the
//! [`Admitted`] they produce. The subjects beside it are [`error`] (the
//! verdict vocabulary and where each refusal points), [`tree`] (the tree
//! flattened in preorder and every interface resolved to the node that
//! fills it), [`fill`] (what stands behind a socket once resolved, and
//! the check every intent clears before ordering), [`order`] (the
//! deterministic interleave), [`node`] (the walk: one pass over the
//! flattened order, and the lowered form it produces), [`edge`] (one
//! value edge crossing into a node), [`inject`] (the entries a
//! resource's own rules put on a frame), and [`abi`] (what a judged
//! frame lowers to for the engine).

mod abi;
mod edge;
mod error;
mod fill;
mod inject;
mod node;
mod order;
mod tree;

use std::collections::BTreeSet;

pub(crate) use edge::{check_instance_value_depth, check_value_depth};
pub use error::{AdmissionError, Placed};
use fill::check_bindings;
pub(crate) use fill::{IntentView, Wired};
use hyperscale_vm_types::{Address, Effect, EffectTarget, IntentHash, Mode};
pub use inject::{Asks, Injected};
use node::{Lowered, lower_all};
pub(crate) use order::interleave;
pub use tree::check_structure;
pub(crate) use tree::{flatten, resolve_tree, walk};

use crate::cells::MARKER_CELL_BYTES;
use crate::claim::Claim;
use crate::dsl::{Condition, Declaration, DeclaredAccess, PresentedGrants};
use crate::hash::{Hash32, Hasher};
use crate::intent::IntentRecord;
use crate::invoke::NodeCall;
use crate::manifest::{JudgedLeaf, Manifest, ManifestHash};
use crate::records::ChainRecords;
use crate::route::FrameDeclaration;
use crate::rule::{Judged, Rule};
use crate::signature::MethodSignature;
use crate::types::child_key;
use crate::vocabulary::AUTH;

/// The bound on sockets one intent may declare. A wire bound.
///
/// An intent binds one edge per socket, so this bounds the binding
/// vector too — which is what makes every socket position expressible
/// as a `u32` index by construction rather than by hope.
pub const MAX_SOCKETS: usize = 32;

/// An admitted tree: the flattened routing manifest, the identity that
/// roots fresh-ID derivation, and every intent's nullifier record.
///
/// The identity is the signed envelope's hash, so distinct signed
/// transactions never mint the same fresh key.
///
/// Only admission constructs one, so "the declaration comes from the fold
/// that admitted it" is a fact about the types rather than a convention
/// callers are asked to keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    manifest: Manifest,
    identity: ManifestHash,
    frames: Vec<FrameDeclaration>,
    injected: Vec<Vec<Injected>>,
    calls: Vec<NodeCall>,
    declaration: Declaration,
    origins: Vec<NodeOrigin>,
    intents: Vec<IntentRecord>,
}

/// Which signed intent a manifest node came from, where in it, and what
/// the signature its call resolved to says about the node's shape.
///
/// The manifest's node order is the interleave the composition chose, so
/// a node's index in it is a fact about the whole tree rather than about
/// the party whose cells the node moves. The intent and the local index
/// are the other reading: content one signer signed, and a position
/// inside it that only that signer can move. What consumes them is
/// escrow-cell derivation: a cell keyed by the manifest index under a
/// transaction hash would take both halves of its material from the
/// composer, who need not be the cell's owner.
///
/// The three signature facts are what the star classifier reads. They
/// are recorded here, where admission holds the resolved signature,
/// rather than re-resolved by the classifier: every replica classifies
/// locally, and a role derived from a chain view that has not yet seen
/// the package would be a divergence waiting for the record to land.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeOrigin {
    /// The signed intent this node belongs to.
    pub intent: IntentHash,
    /// Its index within that intent's own graph.
    pub local: u32,
    /// When the cells this node's crossings write stop being owed: its
    /// intent's own window end plus the retention grace.
    ///
    /// The intent's window and never the transaction's. A transaction's
    /// window is the intersection of every intent's, so this is never
    /// the earlier of the two — and it is signed by the party whose
    /// cells it keys, where the transaction's is the composer's.
    pub expiry_ms: u64,
    /// Whether the method's only movement is one reserve of its own
    /// ([`MethodSignature::is_reservation_shaped`]).
    pub(crate) reservation_shaped: bool,
    /// Whether the method commits nothing at all
    /// ([`MethodSignature::commits_nothing`]).
    pub(crate) commits_nothing: bool,
    /// Whether nothing about a call can refuse ahead of its body, edge
    /// bounds aside ([`MethodSignature::is_unrefusable`]).
    pub(crate) unrefusable: bool,
}

impl NodeOrigin {
    /// The origin of a node at `local` in `intent`, calling `signature`.
    #[must_use]
    pub(crate) fn of(
        intent: IntentHash,
        local: u32,
        expiry_ms: u64,
        signature: &MethodSignature,
    ) -> Self {
        Self {
            intent,
            local,
            expiry_ms,
            reservation_shaped: signature.is_reservation_shaped(),
            commits_nothing: signature.commits_nothing(),
            unrefusable: signature.is_unrefusable(),
        }
    }

    /// The origin of a node in a manifest built by hand rather than
    /// admitted: unsigned, and calling a method nothing is known about,
    /// which the classifier reads as core — the safe direction.
    #[must_use]
    pub(crate) const fn unsigned(local: u32) -> Self {
        Self {
            intent: IntentHash(Hash32([0; 32])),
            local,
            expiry_ms: 0,
            reservation_shaped: false,
            commits_nothing: false,
            unrefusable: false,
        }
    }
}

impl Admitted {
    /// The lowered routing manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The signed form's hash: the transaction identity every fresh
    /// derivation binds to, at admission and at routing alike.
    #[must_use]
    pub const fn identity(&self) -> ManifestHash {
        self.identity
    }

    /// Every evaluated frame's declaration, in node order.
    #[must_use]
    pub fn frames(&self) -> &[FrameDeclaration] {
        &self.frames
    }

    /// One lowered invocation per manifest node, in node order.
    #[must_use]
    pub fn calls(&self) -> &[NodeCall] {
        &self.calls
    }

    /// What the protocol put on each frame, in node order beside
    /// [`frames`](Self::frames).
    ///
    /// Kept rather than dropped because the rule alone cannot say who
    /// asked: it names a key, and a key is a hash that inverts to
    /// nothing. Local to whoever admitted, never signed and never
    /// routed — the shards judge the rules, and only a reader needs the
    /// entry behind one.
    #[must_use]
    pub fn injected(&self) -> &[Vec<Injected>] {
        &self.injected
    }

    /// The transaction's whole declaration, both views: the folded set,
    /// and every frame's clauses concatenated in preorder — the order
    /// capability materialization builds its table in.
    #[must_use]
    pub const fn declaration(&self) -> &Declaration {
        &self.declaration
    }

    /// One record per intent the tree carries, in tree order: its hash
    /// and the nullifier keys whose creation writes make it once-only.
    #[must_use]
    pub fn intents(&self) -> &[IntentRecord] {
        &self.intents
    }

    /// Record the tree's intents beside the manifest they lowered to.
    pub(crate) fn with_intents(mut self, intents: Vec<IntentRecord>) -> Self {
        self.intents = intents;
        self
    }

    /// Declare an effect no signature asked for.
    ///
    /// The kernel's own writes: the exclusive nullifier creation that
    /// makes an intent executable once. It belongs to no
    /// frame, so it carries no clause and no reach, and it lands in the
    /// declaration admission already folded rather than in a second pass
    /// a caller could skip.
    ///
    /// # Panics
    ///
    /// Never: only reserve amounts fold, and these are writes.
    pub(crate) fn push_kernel_effect(&mut self, effect: Effect) {
        self.declaration
            .set
            .insert_bounded(effect, MARKER_CELL_BYTES)
            .expect("only reserve amounts fold, and this is a write");
        self.declaration.ordered.push(DeclaredAccess {
            reach: None,
            effect,
            holds: None,
            clause: None,
        });
    }

    /// Which signed intent each node came from, in node order.
    #[must_use]
    pub fn origins(&self) -> &[NodeOrigin] {
        &self.origins
    }

    /// The owners each node's frame declares, in node order.
    ///
    /// What the decomposition predicate reads: whether a node's
    /// declaration sits inside the scope of the member that runs it is a
    /// per-node question, and the union declaration has already forgotten
    /// which node asked for what.
    #[must_use]
    pub(crate) fn declares(&self) -> Vec<Vec<Address>> {
        self.frames
            .iter()
            .map(|frame| {
                frame
                    .ordered
                    .iter()
                    .map(|access| access.effect.target.owner())
                    .collect()
            })
            .collect()
    }

    /// Whether each node's frame is answered by admission alone, in node
    /// order.
    ///
    /// The lowering already split every condition by where it is judged:
    /// one answerable from committed state joined the union declaration
    /// under this node's number, and every other rides the call. So the
    /// question is a read over the two halves rather than a second walk
    /// over the injection — which has five refusal paths and a hasher,
    /// and would have to be kept in step with admission by hand.
    ///
    /// What consumes it is the star classifier: an outbound leg
    /// materializes after the core committed, so a verdict its frame
    /// reaches at materialization lands on a caller that already
    /// committed.
    #[must_use]
    pub(crate) fn answered_at_admission(&self) -> Vec<bool> {
        let mut answered: Vec<bool> = self
            .calls
            .iter()
            .map(|call| {
                call.requires
                    .iter()
                    .all(|rule| rule.judged() == Judged::AtAdmission)
            })
            .collect();
        for condition in &self.declaration.conditions {
            if let Some(node) = condition.node
                && let Some(slot) = answered.get_mut(node as usize)
            {
                *slot = false;
            }
        }
        answered
    }
}

/// Check every intent's bindings and socket consumption, interleave the
/// intents into one flattened node order over the sockets they declare,
/// and run the node-by-node admission check over that order.
pub(crate) fn admit_intents(
    intents: &[IntentView<'_>],
    identity: ManifestHash,
    chain: &dyn ChainRecords,
    presented: &BTreeSet<Address>,
    grants: &PresentedGrants,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    // Under `MAX_MANIFEST_NODES`: the tree's shape held it there.
    let total: usize = intents.iter().map(|view| view.graph.nodes.len()).sum();

    let wired: Vec<&Wired<'_>> = intents.iter().map(|view| &view.wired).collect();
    check_bindings(&wired)?;

    let interleaved = interleave(&wired, total)?;

    let Lowered {
        consumed,
        nodes,
        frames,
        injected,
        calls,
        origins,
        declaration,
    } = lower_all(
        intents,
        identity,
        chain,
        presented,
        grants,
        hasher,
        &interleaved,
    )?;

    // Every account's sign-in, injected once per account per intent: a
    // read of the account's `auth` cell, and one condition over it
    // against the keys that attested the intent.
    //
    // Judged at materialization on the shard that holds the cell, so it
    // lands before any leg of this transaction commits and every replica
    // of that shard answers it from the same committed bytes. The fee
    // reservation reads the same cell through the same decode and asks a
    // different question — whether the payer's rule admits the signer,
    // before the transaction is included at all — so neither restates
    // the other.
    let mut declaration = declaration;
    for (intent, account) in intents
        .iter()
        .flat_map(|intent| intent.accounts.iter().map(move |account| (intent, account)))
    {
        let cell = child_key(hasher, account.address(), AUTH, &[]);
        let effect = Effect {
            target: EffectTarget::Point(cell),
            mode: Mode::Read,
        };
        declaration.set.insert_at_cap(effect)?;
        declaration.ordered.push(DeclaredAccess {
            effect,
            holds: None,
            reach: None,
            clause: None,
        });
        declaration
            .conditions
            .push(Condition::declared(Rule::Require(JudgedLeaf::Signed {
                cell,
                keys: intent
                    .attested_by
                    .iter()
                    .map(|key| Claim::of_subject(key.address()))
                    .collect(),
            })));
    }

    // Linearity: nothing dangles, yields included.
    for (producer, counts) in consumed.iter().enumerate() {
        for (output, count) in counts.iter().enumerate() {
            if *count == 0 {
                return Err(AdmissionError::UnconsumedOutput {
                    producer: u32::try_from(producer).unwrap_or(u32::MAX),
                    output: u32::try_from(output).unwrap_or(u32::MAX),
                });
            }
        }
    }

    Ok(Admitted {
        manifest: Manifest { nodes },
        identity,
        frames,
        injected,
        calls,
        declaration,
        origins,
        intents: Vec::new(),
    })
}
