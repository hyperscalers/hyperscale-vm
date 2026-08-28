//! The manifest as routing consumes it: typed invocation nodes in
//! topological order, with value flows bound as literals or as edges
//! carrying a static resource type.
//!
//! The graph's full form — typed edges with single-producer/single-consumer
//! linearity and constraint annotations — is admission's concern. Routing
//! reads only what signatures evaluate over: each node's target, method, and
//! bound inputs. Amounts are dynamic; types are static.

use hyperscale_vm_types::{Address, EffectTarget, Presence, ResourceAddr, SubstateKey};

use crate::claim::Claim;
use crate::hash::Hash32;
use crate::rule::{Judged, Leaf};
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
        resource: ResourceAddr,
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
    pub evidence: Vec<Claim>,
}

/// A judged rule's leaf: the evaluated twin of
/// [`RuleLeaf`](crate::rule::RuleLeaf), every expression resolved to the
/// claim a caller must present or the cell a stored rule is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JudgedLeaf {
    /// A claim the presented set must contain.
    Claim(Claim),
    /// The rule stored at this cell, judged where the cell lives. An
    /// unwritten cell holds no rule, and no rule admits nobody: what
    /// governs an address before anything is written there is the
    /// package's own business, declared as a branch beside this leaf.
    /// The account's absent-cell-and-self-claim branch is what makes a
    /// key-derived address govern itself — and what stops admitting the
    /// bare key the moment a rule is stored.
    Stored {
        /// The cell the rule lives in. The declaring method's own
        /// declared access, so it is provisioned wherever the call runs.
        cell: SubstateKey,
    },
    /// The leaf this target names is there, or is not.
    ///
    /// The one leaf whose answer is in the store rather than in what the
    /// call presented, which is what decides where a rule holding it is
    /// judged: a rule made of these alone is answered at materialization,
    /// before any body runs, so it turns no caller away. A value cell
    /// deletes at zero, so presence and a nonzero holding are one fact.
    Presence {
        /// The leaf the question is about.
        target: EffectTarget,
        /// What must be true of it. Never [`Presence::Either`], which
        /// requires nothing.
        expect: Presence,
    },
}

impl Leaf for JudgedLeaf {
    /// A presence's answer is in the store; a claim's is in what the
    /// call presented; a stored rule's is readable only where the
    /// evidence and the session meet.
    fn judged(&self) -> Judged {
        match self {
            Self::Claim(_) => Judged::AtAdmission,
            Self::Stored { .. } => Judged::InTheLeg,
            Self::Presence { .. } => Judged::AtMaterialization,
        }
    }
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

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{
        Address, AddressClass, EffectTarget, LocalKey, Presence, SubstateKey,
    };

    use super::JudgedLeaf;
    use crate::claim::Claim;
    use crate::rule::{Judged, Rule};

    fn cell() -> SubstateKey {
        SubstateKey {
            owner: Address::new([3; 31], AddressClass::Component),
            local: LocalKey([7; 16]),
        }
    }

    fn claim() -> Rule<JudgedLeaf> {
        Rule::Require(JudgedLeaf::Claim(Claim::of_subject(Address::new(
            [9; 31],
            AddressClass::Principal,
        ))))
    }

    fn presence() -> Rule<JudgedLeaf> {
        Rule::Require(JudgedLeaf::Presence {
            target: EffectTarget::Point(cell()),
            expect: Presence::Present,
        })
    }

    fn stored() -> Rule<JudgedLeaf> {
        Rule::Require(JudgedLeaf::Stored { cell: cell() })
    }

    /// Where a rule is judged is the earliest stage that can answer
    /// every leaf it holds, and nothing declares it.
    ///
    /// The three stages know three things. Admission holds the node's
    /// own presented evidence, which is signed content and needs no
    /// state. Materialization holds committed state. Only the walk holds
    /// both, which is why a stored rule and a mixture land there — and
    /// why they are the two a frame whose caller commits without waiting
    /// may not carry.
    #[test]
    fn a_rule_is_judged_at_the_earliest_stage_that_can_answer_it() {
        let two = |left: Rule<JudgedLeaf>, right| Rule::CountOf {
            count: 1,
            rules: vec![left, right],
        };

        assert_eq!(claim().judged(), Judged::AtAdmission);
        assert_eq!(presence().judged(), Judged::AtMaterialization);
        assert_eq!(stored().judged(), Judged::InTheLeg);

        // Nesting changes nothing: the leaves decide, not the tree.
        assert_eq!(two(claim(), claim()).judged(), Judged::AtAdmission);
        assert_eq!(
            two(presence(), presence()).judged(),
            Judged::AtMaterialization
        );

        // A mixture asks about the call and about the state at once, and
        // no earlier stage holds both.
        assert_eq!(two(claim(), presence()).judged(), Judged::InTheLeg);
        assert_eq!(two(claim(), stored()).judged(), Judged::InTheLeg);
        assert_eq!(two(presence(), stored()).judged(), Judged::InTheLeg);

        // The algebra's constants hold no leaves at all, and admission
        // decides those as cheaply as anything else.
        for count in [0, 1] {
            let constant: Rule<JudgedLeaf> = Rule::CountOf {
                count,
                rules: Vec::new(),
            };
            assert_eq!(constant.judged(), Judged::AtAdmission);
        }

        // And only the first two land before any leg commits.
        assert!(Judged::AtAdmission.before_any_leg());
        assert!(Judged::AtMaterialization.before_any_leg());
        assert!(!Judged::InTheLeg.before_any_leg());
    }
}
