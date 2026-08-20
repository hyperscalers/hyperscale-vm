//! The manifest as routing consumes it: typed invocation nodes in
//! topological order, with value flows bound as literals or as edges
//! carrying a static resource type.
//!
//! The graph's full form — typed edges with single-producer/single-consumer
//! linearity and constraint annotations — is admission's concern. Routing
//! reads only what signatures evaluate over: each node's target, method, and
//! bound inputs. Amounts are dynamic; types are static.

use hyperscale_vm_types::{
    Address, CollectionId, Denomination, EffectTarget, Presence, SubstateKey,
};

use crate::auth::RoleId;
use crate::hash::Hash32;
use crate::presented::Presented;
use crate::rule::{Rule, StoredRule};
use crate::types::{EdgeContent, Value};

/// A consumer's signed amount bounds on an edge, folded to their
/// conjunction: the greatest declared lower bound and the least declared
/// upper bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bounds {
    /// The greatest declared lower bound, if any.
    pub min: Option<u128>,
    /// The least declared upper bound, if any.
    pub max: Option<u128>,
}

impl Bounds {
    /// Whether `amount` satisfies both bounds.
    #[must_use]
    pub const fn admits(&self, amount: u128) -> bool {
        let over_min = match self.min {
            Some(min) => amount >= min,
            None => true,
        };
        let under_max = match self.max {
            Some(max) => amount <= max,
            None => true,
        };
        over_min && under_max
    }
}

/// One bound argument of an invocation node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeInput {
    /// A literal from the signed envelope.
    Literal(Value),
    /// An inbound value edge from an earlier node's output. Routing sees
    /// only the edge's static resource type.
    Edge {
        /// The producing node's index; must be earlier than the consumer.
        source: u32,
        /// Which of the producer's outputs this edge carries. A method
        /// with more than one output edge — the bucket splitter, the
        /// book's fill — is indistinguishable from a single-output one
        /// without it, and the walk needs the distinction to hand the
        /// right cell to the consumer.
        output: u32,
        /// The resource type the edge carries.
        resource: Denomination,
        /// What the edge carries besides: a dynamic amount, or the named
        /// instances the producer's evaluated projection declares.
        content: EdgeContent,
        /// The consumer's signed bounds on the amount, folded to their
        /// conjunction at admission.
        ///
        /// These are the manifest's own guarantee, asserted independently
        /// of the callee: a producer that returns less than `min` fails
        /// the transaction whatever its own code checked. Carrying them
        /// into the lowered form is what makes them enforceable —
        /// admission can only judge them against each other, since the
        /// amount does not exist until the producer runs.
        bounds: Bounds,
    },
}

/// A method invocation node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// The target instance, named in the manifest — dynamic dispatch
    /// through state does not exist.
    pub target: Address,
    /// The method to invoke on the target.
    pub method: String,
    /// The node's bound inputs, in the method's parameter order.
    pub inputs: Vec<NodeInput>,
    /// The claims this call presents, resolved from the signed evidence
    /// the node names. Empty for a call requiring none.
    pub evidence: Vec<Presented>,
    /// The gate this call's presented evidence is judged against.
    /// `None` for a method admitting anyone.
    ///
    /// Admission has already checked that a guarded call presents
    /// *something*; whether what it presents satisfies the gate is
    /// answered at execution, against the target.
    pub authority: Option<AuthorityGate>,
}

/// The gate a call's presented evidence is judged against at execution.
///
/// Not `Copy`: a rule is a tree, so a gate is a value a reader borrows
/// rather than one every match arm duplicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityGate {
    /// The presented set must satisfy this rule — what the target itself
    /// named, evaluated at admission with every leaf read off its value's
    /// own class, so a gate naming a configured resource address wants
    /// the badge and one naming three of them can want two.
    Presented(StoredRule),
    /// The presented set must satisfy one of the target's stored rules
    /// at this cell — or, while the cell is absent, carry the identity
    /// the target's address derives. The cell is the method's own
    /// declared point clause, so it is provisioned wherever the call
    /// runs, and which stored rule judges the call is the role its
    /// accessibility names: the primary for an authorizing method, the
    /// named role for a role-gated one. The governing role set is
    /// picked at the transaction clock, so a matured proposal judges
    /// without anything applying it.
    StoredRule {
        /// The cell the target's rules live in.
        cell: SubstateKey,
        /// The stored rule the presented set must satisfy.
        role: RoleId,
    },
    /// The presented set must satisfy the target's stored primary at
    /// `cell` — the holder acts, nobody else presents its badges — and
    /// the target must hold what `possession` names. Both reads are the
    /// method's own declared clauses, keyed by the same expressions the
    /// mint names, so what this gate verifies possession of is exactly
    /// what it mints.
    Custody {
        /// The cell the holder's rules live in; judged as the primary.
        cell: SubstateKey,
        /// What the holder must hold.
        possession: Possession,
    },
}

/// A judged rule's leaf: the evaluated twin of
/// [`RuleLeaf`](crate::rule::RuleLeaf), every expression resolved to the
/// claim a caller must present or the cell a stored rule is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JudgedLeaf {
    /// A claim the presented set must contain.
    Claim(Presented),
    /// The rule stored at this cell under this role, judged where the
    /// cell lives — or, while the cell is absent, the virtual rule: the
    /// identity the cell's owner derives. An absent entry denies.
    Stored {
        /// The cell the stored table lives in. The declaring method's
        /// own declared access, so it is provisioned wherever the call
        /// runs.
        cell: SubstateKey,
        /// The stored rule the presented set must satisfy.
        role: RoleId,
    },
}

/// A declared condition with its expressions evaluated: what the kernel
/// judges, against committed state and the calling node's evidence.
///
/// The two kinds are judged where their raw material lives. A presence
/// condition is judged at materialization, by the shard holding the
/// leaf, beside the presence a write requires; an authority condition is
/// judged at the calling node, with that call's presented evidence,
/// where a gate is judged today.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    /// The leaf this target names is there, or is not.
    Holds {
        /// The leaf the condition is about.
        target: EffectTarget,
        /// What must be true of it. Never [`Presence::Either`], which
        /// requires nothing.
        presence: Presence,
    },
    /// The presented claims satisfy this rule.
    Satisfies {
        /// The rule, its leaves evaluated.
        rule: Rule<JudgedLeaf>,
    },
}

/// What a custody gate reads to decide the holder holds it.
///
/// One leaf either way: the badge is fungible and the vault carries an
/// amount, or it is an instance and the holdings entry at its id is
/// there. A resource is issued as one or the other, so a gate reads one
/// or the other — never an interval standing in for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Possession {
    /// The badge-keyed vault cell: held when its amount is non-zero.
    Vault(SubstateKey),
    /// One entry of the badge-keyed holdings collection: held when the
    /// entry at this id is there.
    Instance {
        /// The collection's owner — the holder itself.
        owner: Address,
        /// The badge-keyed holdings collection.
        holdings: CollectionId,
        /// Which instance, as the entry's own order key.
        id: u64,
    },
}

/// A manifest: invocation nodes in topological order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    /// The invocation nodes; an edge's source index is always smaller than
    /// its consumer's.
    pub nodes: Vec<Node>,
}

/// A transaction's identity: the signed graph's hash.
///
/// Computed through the hasher seam, so the eventual wire encoding can
/// change beneath it. Fresh-ID derivation roots here — the signed form,
/// covering constraints, never the lowered manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestHash(pub Hash32);
