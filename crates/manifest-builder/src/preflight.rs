//! Preflight: the chain's whole verdict on a transaction, before it is
//! signed.
//!
//! Everything downstream of the signed form is a pure function of the form
//! and content-addressed metadata — that is what lets every node reach the
//! identical verdict, and it lets a client reach it too. Nothing here
//! computes anything new. Admission, routing, the footprint schedule and
//! the declared authorities all exist already; this composes them into one
//! call and one report, so a wallet asks its question once instead of
//! learning the shape of four APIs.
//!
//! What comes back is a report, never a judgement. Whether to sign is the
//! holder's, and a report that names an unsatisfiable authority still
//! describes the transaction rather than refusing to.
//!
//! The network word is an input. A report names addresses, an address's
//! text form is scoped to the network it is read on, and there is no
//! default to fall back on — so it is supplied where the report is asked
//! for, and a word the encoding refuses fails once here rather than at
//! every address.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::{
    AdmissionError, Admitted, ChainRecords, EnvelopeTree, Hasher, JudgedLeaf, Manifest,
    ManifestGraph, ManifestHash, Presented, Routing, Rule, ShardId, ShardResolver, SubintentRecord,
    admit, admit_tree, footprint, route, route_tree,
};
use hyperscale_vm_types::{
    Address, CallTarget, EffectTarget, NetworkWord, Presence, PrincipalAddr, ResourceAddr,
    SchemeId, SubstateKey, TextError, declared_work, signature_work,
};

/// Why a transaction could not be preflighted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PreflightError {
    /// The signed form is one admission would refuse.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// A network word no address can be named under.
    #[error(transparent)]
    Network(#[from] TextError),
}

/// Whose signature naming one node requires.
///
/// Read off the authority gate admission resolved for the node — the
/// same verdict execution judges, over the same bound inputs — which is
/// the only thing that knows: an address is a hash, so nothing about a
/// target can be read from the address itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authority {
    /// Anyone may name this method on this target. What the caller
    /// supplies was gated wherever it was obtained.
    Anyone,
    /// A signature this principal's address derives.
    Signature(PrincipalAddr),
    /// The target's stored rule for this role. While nothing is stored,
    /// that is the identity the target's address derives — its own
    /// signature — but once the target is securified the stored role
    /// set governs, and only state knows its shape.
    StoredRule,
    /// A credential the mover must hold: a leaf under their own prefix
    /// whose presence is the whole question. Nothing is presented for
    /// it, so a builder reports it rather than routing evidence to it.
    Held,
    /// An identity no key derives — an instance's own address, or a
    /// configured slot holding one. Nothing signs for a hash of what an
    /// object is, so a method requiring one cannot be named by anyone.
    TargetHasNoKey,
    /// A badge the caller must present: possession of the resource, or
    /// of the one instance of it named here. No signature satisfies it
    /// on its own — the holder presents it through a custodial call,
    /// which the same report shows as a node of its own.
    Badge {
        /// The badge resource.
        resource: ResourceAddr,
        /// The instance named, where the gate names one rather than the
        /// resource at large.
        instance: Option<u64>,
    },
    /// A threshold the method itself declares: `count` of `branches`,
    /// each a claim of its own. What satisfies which branch is the
    /// holder's to know, so the report states the shape rather than
    /// choosing a way through it.
    Threshold {
        /// How many branches must be satisfied.
        count: u8,
        /// How many there are.
        branches: u32,
    },
}

/// What one node of the flattened manifest requires of a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Required {
    /// The node's index in the flattened manifest.
    pub node: u32,
    /// The instance the method runs on.
    pub target: Address,
    /// The method named.
    pub method: String,
    /// Whose authority naming it requires.
    pub authority: Authority,
}

/// The cell a governing rule reads, where a rule is one.
///
/// Recognised by shape because the shape is the vocabulary's own idiom
/// rather than one author's: a stored rule beside the address's own
/// identity, the second arm reachable only while the first has nothing
/// to read. What a holder is owed is that this asks the target's stored
/// rule, not that it took two branches to say so.
fn governing(rule: &Rule<JudgedLeaf>) -> Option<SubstateKey> {
    let Rule::CountOf { count: 1, rules } = rule else {
        return None;
    };
    let [
        Rule::Require(JudgedLeaf::Stored { cell }),
        Rule::CountOf {
            count: 2,
            rules: fallback,
        },
    ] = rules.as_slice()
    else {
        return None;
    };
    let [
        Rule::Require(JudgedLeaf::Presence {
            target: EffectTarget::Point(absent),
            expect: Presence::Absent,
        }),
        Rule::Require(JudgedLeaf::Claim(_)),
    ] = fallback.as_slice()
    else {
        return None;
    };
    (absent == cell).then_some(*cell)
}

/// Everything a holder can know before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The network the text forms in [`named`](Self::named) are read on.
    pub network: NetworkWord,
    /// The admitted form: the lowered manifest and the identity every
    /// fresh derivation — and every signature — binds to.
    pub admitted: Admitted,
    /// The routing: per-shard declared effects, evaluated frames, the
    /// lowered call list, and the static call graph.
    pub routing: Routing,
    /// What each participating shard's declaration costs on the footprint
    /// schedule.
    pub footprints: BTreeMap<ShardId, u64>,
    /// What naming each node requires of a signature, in node order.
    pub authority: Vec<Required>,
    /// The nullifier record of every bound subintent, empty for a bare
    /// graph.
    pub subintents: Vec<SubintentRecord>,
    /// Every address the report names, in this network's text form.
    pub named: BTreeMap<Address, String>,
}

impl Report {
    /// The lowered routing manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        self.admitted.manifest()
    }

    /// The identity a signature covers.
    #[must_use]
    pub const fn identity(&self) -> ManifestHash {
        self.admitted.identity()
    }

    /// The shards this transaction touches.
    pub fn shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.footprints.keys().copied()
    }

    /// The whole declared footprint: the sum over participating shards,
    /// because the reservation is taken once against all of it rather than
    /// per shard.
    #[must_use]
    pub fn footprint(&self) -> u64 {
        self.footprints
            .values()
            .fold(0, |total, shard| total.saturating_add(*shard))
    }

    /// What this transaction costs a block at `gas_limit` under
    /// `schemes`: the fixed carry charge, the footprint it declares, the
    /// ceiling it would sign for its own execution, and what the
    /// signatures it will carry cost to check.
    ///
    /// `schemes` names one entry per signature the envelope will bind —
    /// the composer's and each bound subintent signer's. Neither it nor
    /// the ceiling can be read off the graph: both are the signer's own
    /// choices, so both are asked for here rather than reported.
    #[must_use]
    pub fn declared_work(&self, gas_limit: u64, schemes: &[SchemeId]) -> u64 {
        let signatures = schemes.iter().fold(0u64, |total, scheme| {
            total.saturating_add(signature_work(*scheme))
        });
        declared_work(self.footprint(), gas_limit, signatures)
    }

    /// Every signature the transaction needs: what its nodes' declared
    /// access requires, plus the signer of every bound subintent. A
    /// rule-judged node contributes its target's own key — the identity
    /// that satisfies the rule while nothing is stored; a securified
    /// target's stored rules name their signers in state, which no
    /// report reads.
    #[must_use]
    pub fn signers(&self) -> BTreeSet<PrincipalAddr> {
        self.authority
            .iter()
            .filter_map(|required| match required.authority {
                Authority::Signature(principal) => Some(principal),
                Authority::StoredRule => PrincipalAddr::try_from(required.target).ok(),
                Authority::Anyone
                | Authority::TargetHasNoKey
                | Authority::Held
                | Authority::Badge { .. }
                | Authority::Threshold { .. } => None,
            })
            .chain(self.subintents.iter().map(|record| record.signer))
            .collect()
    }

    /// The nodes whose access no signature can satisfy. A transaction
    /// carrying one cannot be made to succeed by signing it differently.
    pub fn unsatisfiable(&self) -> impl Iterator<Item = &Required> {
        self.authority
            .iter()
            .filter(|required| matches!(required.authority, Authority::TargetHasNoKey))
    }

    /// An address the report names, in this network's text form.
    #[must_use]
    pub fn text(&self, address: impl Into<Address>) -> Option<&str> {
        self.named.get(&address.into()).map(String::as_str)
    }
}

/// The whole verdict on a bare graph, before signing.
///
/// # Errors
///
/// [`PreflightError::Admission`] or [`PreflightError::Route`] for a
/// transaction the chain would refuse, and [`PreflightError::Network`] for
/// a network word no address can be named under.
pub fn preflight(
    graph: &ManifestGraph,
    composer: PrincipalAddr,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
    shards: &dyn ShardResolver,
    network: &str,
) -> Result<Report, PreflightError> {
    let admitted = admit(graph, composer, chain, hasher)?;
    let routing = route(&admitted, shards);
    report(admitted, routing, Vec::new(), network)
}

/// The same verdict on a composed envelope, whose subintent records name
/// the nullifier each one spends.
///
/// # Errors
///
/// As [`preflight`].
pub fn preflight_tree(
    tree: &EnvelopeTree,
    composer: PrincipalAddr,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
    shards: &dyn ShardResolver,
    network: &str,
) -> Result<Report, PreflightError> {
    let identity = tree.hash(hasher);
    let admitted = admit_tree(tree, composer, identity, chain, hasher)?;
    let routing = route_tree(&admitted, shards);
    report(admitted.admitted, routing, admitted.subintents, network)
}

/// Assemble the report both entry points answer with.
fn report(
    admitted: Admitted,
    routing: Routing,
    subintents: Vec<SubintentRecord>,
    network: &str,
) -> Result<Report, PreflightError> {
    let footprints = routing
        .per_shard
        .iter()
        .map(|(shard, declared)| (*shard, footprint(declared)))
        .collect();

    // What one claim asks of a signer: a principal's address derives
    // from its key material, so its own authority is a signature; every
    // other class derives from a hash of what it is, and nothing signs
    // for that.
    // What a claim's subject is, is its class's answer, asked here
    // because here is where it matters.
    let claimed = |claim: &Presented| match (claim.badge(), claim.callable()) {
        (Some(resource), _) => Authority::Badge {
            resource,
            instance: claim.instance,
        },
        (None, Some(CallTarget::Principal(principal))) => Authority::Signature(principal),
        (None, Some(CallTarget::Component(_)) | None) => Authority::TargetHasNoKey,
    };

    // The authority gate admission resolved for each node, read back
    // rather than re-derived: the report answers with the verdict
    // execution will judge, over the node's real bound inputs. A
    // principal's address derives from its key material, so its own
    // authority is a signature; every other class derives from a hash of
    // what it is, and nothing signs for that.
    let mut authority = Vec::with_capacity(admitted.manifest().nodes.len());
    for (index, node) in admitted.manifest().nodes.iter().enumerate() {
        let required = match admitted.calls()[index].requires.as_slice() {
            [] => Authority::Anyone,
            [Rule::Require(JudgedLeaf::Claim(claim))] => claimed(claim),
            [Rule::Require(JudgedLeaf::Stored { .. })] => Authority::StoredRule,
            [Rule::Require(JudgedLeaf::Presence { .. })] => Authority::Held,
            // The governing idiom: the rule stored at a cell, or — while
            // nothing is stored there — the identity that address itself
            // derives. Two branches, one question, and a holder is owed
            // the question rather than the spelling.
            [rule] if governing(rule).is_some() => Authority::StoredRule,
            // A threshold names more than one thing, and which of them a
            // holder can produce is theirs to know: the report says what
            // is asked rather than picking a way to satisfy it.
            [Rule::CountOf { count, rules }] => Authority::Threshold {
                count: *count,
                branches: u32::try_from(rules.len()).unwrap_or(u32::MAX),
            },
            // Several required rules conjoin, so the report says how
            // many are asked and that all of them are.
            rules => Authority::Threshold {
                count: u8::try_from(rules.len()).unwrap_or(u8::MAX),
                branches: u32::try_from(rules.len()).unwrap_or(u32::MAX),
            },
        };
        authority.push(Required {
            node: u32::try_from(index).unwrap_or(u32::MAX),
            target: node.target,
            method: node.method.clone(),
            authority: required,
        });
    }

    // Every address the report names, rendered once so a network word the
    // encoding refuses fails here rather than at a display seam.
    let mut named = BTreeMap::new();
    let addresses = authority
        .iter()
        .map(|required| required.target)
        .chain(
            authority
                .iter()
                .filter_map(|required| match required.authority {
                    Authority::Signature(principal) => Some(principal.address()),
                    _ => None,
                }),
        )
        .chain(subintents.iter().map(|record| record.signer.address()));
    for address in addresses {
        if let Entry::Vacant(slot) = named.entry(address) {
            slot.insert(address.to_text(network)?);
        }
    }

    Ok(Report {
        network: NetworkWord(network.to_owned()),
        admitted,
        routing,
        footprints,
        authority,
        subintents,
        named,
    })
}
