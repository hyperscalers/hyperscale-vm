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
    AdmissionError, Admitted, ChainRecords, Claim, EnvelopeTree, Hasher, JudgedLeaf, Manifest,
    ManifestHash, Rule, SubintentRecord, admit_tree, footprint,
};
use hyperscale_vm_types::{
    Address, CallTarget, DeclaredWork, EffectTarget, Mode, NetworkWord, Presence, PriceTable,
    PrincipalAddr, ResourceAddr, SchemeId, SubintentHash, SubstateKey, TermsRefusal, TextError,
    admit_ceilings, admit_event_bounds, gas_limit_total,
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
    /// A signed term the chain would refuse the envelope for.
    #[error(transparent)]
    Terms(#[from] TermsRefusal),
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
    /// object is, so a method requiring one cannot be named by anyone —
    /// except by carrying a proof that instance's own method proved,
    /// which is [`ProvenInTransaction`](Self::ProvenInTransaction).
    TargetHasNoKey,
    /// An identity no key derives, whose claim this node nonetheless
    /// carries: a claim proven inside the transaction — the venue and
    /// registrar pattern — resolved from the node's own presented
    /// evidence. Satisfiable because it is already satisfied, so it
    /// never lands in [`Report::unsatisfiable`].
    ProvenInTransaction,
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
    /// A threshold: `count` of `branches`, each an authority of its own.
    /// Which branches a holder satisfies is theirs to choose, so the
    /// report states every branch rather than picking a way through —
    /// and a conjunction is the threshold whose count is its width,
    /// where each branch is asked and the report says which.
    Threshold {
        /// How many branches must be satisfied.
        count: u8,
        /// What each branch asks.
        branches: Vec<Self>,
    },
}

impl Authority {
    /// Whether anything a holder could sign or present satisfies this.
    ///
    /// [`TargetHasNoKey`](Self::TargetHasNoKey) is satisfied by nobody,
    /// and a threshold only where enough of its branches are.
    #[must_use]
    pub fn satisfiable(&self) -> bool {
        match self {
            Self::TargetHasNoKey => false,
            Self::Threshold { count, branches } => {
                branches
                    .iter()
                    .filter(|branch| branch.satisfiable())
                    .count()
                    >= usize::from(*count)
            }
            Self::Anyone
            | Self::Signature(_)
            | Self::StoredRule
            | Self::Held
            | Self::ProvenInTransaction
            | Self::Badge { .. } => true,
        }
    }

    /// The signatures satisfying this authority certainly requires, into
    /// `out`.
    ///
    /// A conjunction needs every branch, so each contributes; a
    /// threshold below its width leaves the choice with the holder and
    /// contributes none. A rule-judged branch contributes the target's
    /// own key — the identity that satisfies the rule while nothing is
    /// stored.
    fn certain_signers(&self, target: Address, out: &mut BTreeSet<PrincipalAddr>) {
        match self {
            Self::Signature(principal) => {
                out.insert(*principal);
            }
            Self::StoredRule => {
                if let Ok(principal) = PrincipalAddr::try_from(target) {
                    out.insert(principal);
                }
            }
            Self::Threshold { count, branches } if usize::from(*count) == branches.len() => {
                for branch in branches {
                    branch.certain_signers(target, out);
                }
            }
            Self::Anyone
            | Self::TargetHasNoKey
            | Self::ProvenInTransaction
            | Self::Held
            | Self::Badge { .. }
            | Self::Threshold { .. } => {}
        }
    }

    /// Every address this authority names, into `out` — what
    /// [`Report::named`] renders, however deep in a threshold it sits.
    fn names(&self, out: &mut Vec<Address>) {
        match self {
            Self::Signature(principal) => out.push(principal.address()),
            Self::Badge { resource, .. } => out.push(resource.address()),
            Self::Threshold { branches, .. } => {
                for branch in branches {
                    branch.names(out);
                }
            }
            Self::Anyone
            | Self::StoredRule
            | Self::Held
            | Self::TargetHasNoKey
            | Self::ProvenInTransaction => {}
        }
    }
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
fn required_rule(rule: &Rule<JudgedLeaf>) -> Option<SubstateKey> {
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

/// What one claim asks of a signer.
///
/// A principal's address derives from its key material, so its own
/// authority is a signature; a badge is presented rather than signed
/// for; every other class derives from a hash of what it is, and
/// nothing signs for that. What a claim's subject is, is its class's
/// answer, asked here because here is where it matters.
fn claimed(claim: &Claim, evidence: &[Claim]) -> Authority {
    match (claim.badge(), claim.callable()) {
        (Some(resource), _) => Authority::Badge {
            resource,
            instance: claim.instance,
        },
        (None, Some(CallTarget::Principal(principal))) => Authority::Signature(principal),
        // Nothing signs for a hash of what an object is — but the
        // object's own methods mint proofs of it, and a node already
        // carrying one is the venue pattern, not a dead end.
        (None, Some(CallTarget::Component(_)) | None) => {
            if evidence.contains(claim) {
                Authority::ProvenInTransaction
            } else {
                Authority::TargetHasNoKey
            }
        }
    }
}

/// The authority one resolved rule asks for, thresholds carrying what
/// each branch asks in turn.
///
/// The governing idiom answers first: the rule stored at a cell, or —
/// while nothing is stored there — the identity that address itself
/// derives. Two branches, one question, and a holder is owed the
/// question rather than the spelling. The recursion is bounded by the
/// caps every rule is decoded and evaluated under.
fn authority_of(rule: &Rule<JudgedLeaf>, evidence: &[Claim]) -> Authority {
    if required_rule(rule).is_some() {
        return Authority::StoredRule;
    }
    match rule {
        Rule::Require(JudgedLeaf::Claim(claim)) => claimed(claim, evidence),
        Rule::Require(JudgedLeaf::Stored { .. }) => Authority::StoredRule,
        Rule::Require(JudgedLeaf::Presence { .. }) => Authority::Held,
        Rule::CountOf { count, rules } => Authority::Threshold {
            count: *count,
            branches: rules
                .iter()
                .map(|rule| authority_of(rule, evidence))
                .collect(),
        },
    }
}

/// One manifest node's compute ceiling, beside the intent whose node it
/// is: one row of the report's compute column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeCompute {
    /// The manifest node, in the order the walk meters them.
    pub node: u32,
    /// The signed intent the node came from.
    pub intent: SubintentHash,
    /// The ceiling the composer would sign for it, in fuel.
    pub ceiling: u64,
}

/// Everything a holder can know before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The network the text forms in [`named`](Self::named) are read on.
    pub network: NetworkWord,
    /// The admitted form: the lowered manifest and the identity every
    /// fresh derivation — and every signature — binds to.
    pub admitted: Admitted,
    /// The composer: the root intent's signer, and the one payer.
    pub composer: PrincipalAddr,
    /// The root intent's own hash.
    ///
    /// Taken from the declaration rather than found as the one intent
    /// the subintent records do not name: a root whose sockets carry the
    /// whole composition declares no nodes of its own, and an intent
    /// with no nodes appears in no origin to be found by.
    pub root_intent: SubintentHash,
    /// What naming each node requires of a signature, in node order.
    pub authority: Vec<Required>,
    /// The nullifier record of every bound subintent, empty where the
    /// tree binds none.
    pub subintents: Vec<SubintentRecord>,
    /// What the methods this transaction's calls name may emit between
    /// them, in bytes.
    ///
    /// Read off each call's own method, summed and held under the cap
    /// the chain holds it under — a manifest whose calls sum past it is
    /// refused here as it would be at derivation. Retained bytes like
    /// the writes beside them, so a quote that left it out would name a
    /// ceiling the chain then prices past.
    pub event_bytes: u64,
    /// What each call's own method may emit, in node order.
    ///
    /// The term [`event_bytes`](Self::event_bytes) is the sum of, kept
    /// per node because a node belongs to exactly one intent — so this
    /// is the one retention term an intent can be held to on its own.
    pub event_bytes_by_node: Vec<u32>,
    /// Every address the report names, in this network's text form.
    pub named: BTreeMap<Address, String>,
}

/// What one signed intent contributes on its own, from
/// [`Report::by_intent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentCost {
    /// The intent this is about.
    pub intent: SubintentHash,
    /// How many of the flattened manifest's nodes are this intent's.
    pub nodes: u32,
    /// Its nodes' signed ceilings, summed.
    pub compute: u64,
    /// What its calls' own methods may emit between them.
    pub event_bytes: u64,
    /// Whose signature admits it: the composer for the root, the
    /// subintent's own signer otherwise.
    ///
    /// The signer and not the signature's cost. What a signature weighs
    /// depends on its scheme, and an intent is not held to one — a
    /// conjunction asks several parties for one node, so the signatures
    /// an envelope binds are not one per intent and pairing them
    /// positionally would put one intent's scheme against another's.
    /// A caller that has chosen the schemes knows which belong to whom
    /// and can price them with [`DeclaredWork::signature`].
    pub signer: PrincipalAddr,
    /// The most this intent's own nodes may move out, by resource.
    ///
    /// The reserves they declare, which is the whole of what its signer
    /// agreed to risk by being composed: a reserve names its amount in
    /// the declaration, so it is signed and a composition cannot raise
    /// it. What the composition does with the value is the composer's;
    /// the bound is the signer's.
    pub exposure: BTreeMap<ResourceAddr, u128>,
    /// Whether any of its nodes moves value out of one of the signer's
    /// own cells under a mode that declares no amount, which makes
    /// [`exposure`](Self::exposure) a floor rather than the bound.
    ///
    /// A delta's amount is dynamic and never part of a declaration, so
    /// an intent carrying an outward one has signed no ceiling on what
    /// leaves. Reported rather than folded in, because there is no
    /// figure to fold: what a reader needs is that the number beside it
    /// is not the answer.
    ///
    /// **Nothing reaches it today**, and no test pins it true. A
    /// signer's cells are their account's, the account package is what
    /// serves every principal, and its only outward movement is a
    /// reserve — so every shape the stdlib can build makes `exposure`
    /// the whole bound. It is here because that is a fact about one
    /// package's methods and not a structural one: an account method
    /// that debited a vault by a dynamic amount would make the figure
    /// beside it a floor, and silence would be the wrong answer.
    pub unbounded_outflow: bool,
}

/// The per-intent breakdown beside what no one intent owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByIntent {
    /// One entry per signed intent: the root first, then each bound
    /// subintent in envelope order.
    pub intents: Vec<IntentCost>,
    /// The cells more than one intent declares, ascending.
    ///
    /// Named rather than divided: the declaration is a set, so these are
    /// paid for once by the transaction and belong to none of its
    /// intents alone.
    pub shared: Vec<EffectTarget>,
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

    /// The whole declared footprint. The reservation is taken once
    /// against all of it, and a target's accesses all resolve to one
    /// shard, so the figure is the declaration's own rather than a sum
    /// over a partition of it.
    #[must_use]
    pub fn footprint(&self) -> u64 {
        footprint(&self.admitted.declaration().set)
    }

    /// The bytes the declaration lets execution read off the store: the
    /// disk's dimension of the vector, before the artifacts the calls
    /// instantiate.
    #[must_use]
    pub fn read_bytes(&self) -> u64 {
        self.admitted.declaration().set.read_bytes()
    }

    /// The bytes the declaration leaves behind on the store: what
    /// retention keeps, as against what [`write_bytes`](Self::write_bytes)
    /// costs to put there.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.admitted.declaration().set.retained_bytes()
    }

    /// The bytes the declaration lets execution write onto the store.
    #[must_use]
    pub fn write_bytes(&self) -> u64 {
        self.admitted.declaration().set.write_bytes()
    }

    /// What this transaction would declare, signed at `gas_limits` under
    /// `schemes`, with `artifact_bytes` of package code behind its calls.
    ///
    /// `schemes` names one entry per signature the envelope will bind,
    /// which is one per party in [`Self::signers`] and not one per
    /// intent: a conjunction asks several parties for one node, so an
    /// intent can need more than one and the two counts part company as
    /// soon as one does. The chain counts the signatures the envelope
    /// actually carries, so a short vector understates the quote rather
    /// than the charge — a wallet that passes one scheme per intent
    /// signs a ceiling admission then refuses. `artifact_bytes` is
    /// the length of every distinct package the calls
    /// run, once each. Neither can be read off the graph and the chain
    /// records here: the ceilings and the schemes are the composer's own
    /// choices, and the records serve metadata rather than code, so all
    /// three are asked for rather than reported. The envelope's own
    /// length is the one term missing: the report is asked before the
    /// envelope exists, and what the signer adds around the tree is
    /// theirs to add to the retention.
    #[must_use]
    pub fn work(
        &self,
        gas_limits: &[u64],
        schemes: &[SchemeId],
        artifact_bytes: u64,
    ) -> DeclaredWork {
        let signatures = schemes.iter().fold(DeclaredWork::ZERO, |total, scheme| {
            total.saturating_add(DeclaredWork::signature(*scheme))
        });
        DeclaredWork {
            compute: gas_limit_total(gas_limits),
            read_bytes: self.read_bytes().saturating_add(artifact_bytes),
            write_bytes: self.write_bytes(),
            footprint: self.footprint(),
            retention: self.retained_bytes().saturating_add(self.event_bytes),
        }
        .saturating_add(signatures)
    }

    /// What this transaction would be charged, in quanta, under `table`
    /// at `priority_bp`: [`Self::work`] at the table's rows. The figure a
    /// signed fee ceiling has to cover, or admission refuses the
    /// envelope.
    #[must_use]
    pub fn price(
        &self,
        table: &PriceTable,
        gas_limits: &[u64],
        schemes: &[SchemeId],
        artifact_bytes: u64,
        priority_bp: u32,
    ) -> u128 {
        table.price(&self.work(gas_limits, schemes, artifact_bytes), priority_bp)
    }

    /// The compute column: each node's ceiling from `gas_limits`, in node
    /// order, beside the intent it belongs to — so a composer reads what
    /// each bound intent's nodes would cost them under the ceilings they
    /// are about to sign.
    ///
    /// # Errors
    ///
    /// [`TermsRefusal`] where `gas_limits` is not one per node or sums
    /// past the bound: the refusal the derivation would give the signed
    /// envelope, given here before it is signed.
    pub fn compute(&self, gas_limits: &[u64]) -> Result<Vec<NodeCompute>, TermsRefusal> {
        admit_ceilings(gas_limits, self.manifest().nodes.len())?;
        Ok(self
            .admitted
            .origins()
            .iter()
            .zip(gas_limits)
            .enumerate()
            .map(|(index, (origin, ceiling))| NodeCompute {
                node: u32::try_from(index).unwrap_or(u32::MAX),
                intent: origin.intent,
                ceiling: *ceiling,
            })
            .collect())
    }

    /// What each signed intent contributes, in the dimensions that are
    /// its own, beside the cells no single intent owns.
    ///
    /// The composer's root intent first, then each bound subintent in
    /// envelope order.
    ///
    /// **Three dimensions are deliberately absent.** A declaration is a
    /// set keyed by target — two intents naming one cell are one access,
    /// which is what makes the transaction pay for it once — so the read
    /// bytes, the write bytes and the footprint of a shared cell belong
    /// to no intent in particular. Splitting them would give a composer
    /// figures that do not sum to what the chain charges, which is worse
    /// than giving none: the use for these is pricing a cut. What is
    /// here is what a node owns outright — its ceiling and what its
    /// method may emit — plus the one signature its signer binds. What
    /// is shared is named in [`ByIntent::shared`] rather than divided.
    ///
    /// # Errors
    ///
    /// As [`Self::compute`].
    pub fn by_intent(&self, gas_limits: &[u64]) -> Result<ByIntent, TermsRefusal> {
        let compute = self.compute_by_intent(gas_limits)?;
        let origins = self.admitted.origins();

        // Whose signature admits each intent.
        let order: Vec<(SubintentHash, PrincipalAddr)> =
            std::iter::once((self.root_intent, self.composer))
                .chain(
                    self.subintents
                        .iter()
                        .map(|record| (record.subintent, record.signer)),
                )
                .collect();
        let owner_of: BTreeMap<SubintentHash, Address> = order
            .iter()
            .map(|(intent, signer)| (*intent, signer.address()))
            .collect();

        let mut events: BTreeMap<SubintentHash, u64> = BTreeMap::new();
        for (origin, bound) in origins.iter().zip(&self.event_bytes_by_node) {
            let total = events.entry(origin.intent).or_default();
            *total = total.saturating_add(u64::from(*bound));
        }

        // What each intent declares may leave cells its own signer owns.
        //
        // Off the frames rather than the routed set, because the set
        // unions across intents and a reserve is exactly what must not
        // be pooled: the figure is one signer's agreed risk.
        //
        // And scoped to the signer's own cells, because a node's frame
        // declares every cell the call touches — a swap debits the
        // venue's reserve, which is the venue's value moving and not the
        // caller's. What a signer risks is what leaves an address they
        // hold.
        let mut exposure: BTreeMap<SubintentHash, BTreeMap<ResourceAddr, u128>> = BTreeMap::new();
        let mut unbounded: BTreeSet<SubintentHash> = BTreeSet::new();
        for frame in self.admitted.frames() {
            let Some(origin) = origins.get(frame.node as usize) else {
                continue;
            };
            for access in &frame.ordered {
                let Some(resource) = access.holds else {
                    continue;
                };
                if owner_of.get(&origin.intent) != Some(&access.effect.target.owner()) {
                    continue;
                }
                match access.effect.mode {
                    Mode::Reserve { amount } => {
                        let total = exposure
                            .entry(origin.intent)
                            .or_default()
                            .entry(resource)
                            .or_default();
                        *total = total.saturating_add(amount);
                    }
                    Mode::Delta { moves } | Mode::Write { moves } if moves.debits() => {
                        unbounded.insert(origin.intent);
                    }
                    _ => {}
                }
            }
        }

        // A target every intent that reaches it, so a cell two of them
        // name is readable as the shared thing it is.
        let mut reached: BTreeMap<EffectTarget, BTreeSet<SubintentHash>> = BTreeMap::new();
        for frame in self.admitted.frames() {
            let Some(origin) = origins.get(frame.node as usize) else {
                continue;
            };
            for access in &frame.ordered {
                reached
                    .entry(access.effect.target)
                    .or_default()
                    .insert(origin.intent);
            }
        }
        let shared = reached
            .into_iter()
            .filter(|(_, intents)| intents.len() > 1)
            .map(|(target, _)| target)
            .collect();

        let intents = order
            .into_iter()
            .map(|(intent, signer)| IntentCost {
                nodes: u32::try_from(
                    origins
                        .iter()
                        .filter(|origin| origin.intent == intent)
                        .count(),
                )
                .unwrap_or(u32::MAX),
                compute: compute.get(&intent).copied().unwrap_or(0),
                event_bytes: events.get(&intent).copied().unwrap_or(0),
                signer,
                exposure: exposure.get(&intent).cloned().unwrap_or_default(),
                unbounded_outflow: unbounded.contains(&intent),
                intent,
            })
            .collect();

        Ok(ByIntent { intents, shared })
    }

    /// The compute column folded per intent: what each signed intent's
    /// nodes would cost the composer, keyed by the intent.
    ///
    /// # Errors
    ///
    /// As [`Self::compute`].
    pub fn compute_by_intent(
        &self,
        gas_limits: &[u64],
    ) -> Result<BTreeMap<SubintentHash, u64>, TermsRefusal> {
        let mut by_intent = BTreeMap::new();
        for row in self.compute(gas_limits)? {
            let total: &mut u64 = by_intent.entry(row.intent).or_default();
            *total = total.saturating_add(row.ceiling);
        }
        Ok(by_intent)
    }

    /// Every signature the transaction certainly needs: what its nodes'
    /// declared access requires, plus the signer of every bound
    /// subintent. A rule-judged node contributes its target's own key,
    /// which is the identity that satisfies the rule while nothing is
    /// stored and a guess once something is: a securified target's
    /// stored rule names its signers in state, which no report reads,
    /// so the key named here may open nothing. A threshold below its
    /// width leaves the choice with the holder, so only a conjunction's
    /// branches contribute.
    #[must_use]
    pub fn signers(&self) -> BTreeSet<PrincipalAddr> {
        let mut signers: BTreeSet<PrincipalAddr> =
            self.subintents.iter().map(|record| record.signer).collect();
        for required in &self.authority {
            required
                .authority
                .certain_signers(required.target, &mut signers);
        }
        signers
    }

    /// The nodes whose access no signature can satisfy. A transaction
    /// carrying one cannot be made to succeed by signing it differently.
    pub fn unsatisfiable(&self) -> impl Iterator<Item = &Required> {
        self.authority
            .iter()
            .filter(|required| !required.authority.satisfiable())
    }

    /// An address the report names, in this network's text form.
    #[must_use]
    pub fn text(&self, address: impl Into<Address>) -> Option<&str> {
        self.named.get(&address.into()).map(String::as_str)
    }
}

/// The whole verdict on a composed envelope, before signing.
///
/// Only a tree, never a bare graph: every intent carries a signed header,
/// so what the chain admits is always a tree and the identity every
/// fresh derivation and every signature binds to is the tree's hash. A
/// verdict on the graph alone would report keys the chain will not
/// derive and withhold records the tree carries. One intent with no
/// sockets is the degenerate tree a plain transaction is.
///
/// # Errors
///
/// [`PreflightError::Admission`] for a transaction the chain would
/// refuse, and [`PreflightError::Network`] for a network word no address
/// can be named under.
pub fn preflight_tree(
    tree: &EnvelopeTree,
    composer: PrincipalAddr,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
    network: &str,
) -> Result<Report, PreflightError> {
    let identity = tree.hash(hasher);
    let admitted = admit_tree(tree, composer, identity, chain, hasher)?;
    report(
        admitted.admitted,
        composer,
        tree.root.hash(hasher),
        admitted.subintents,
        chain,
        network,
    )
}

/// Assemble the report.
fn report(
    admitted: Admitted,
    composer: PrincipalAddr,
    root_intent: SubintentHash,
    subintents: Vec<SubintentRecord>,
    chain: &dyn ChainRecords,
    network: &str,
) -> Result<Report, PreflightError> {
    // What each call's own method may emit, on the rule the chain
    // applies: a method that states nothing may emit nothing, and the
    // sum is what retention prices. A package this node has not seen
    // contributes nothing rather than guessing — the same call would
    // not have admitted above.
    let per_call: Vec<u32> = admitted
        .calls()
        .iter()
        .map(|call| {
            chain
                .package(call.package)
                .and_then(|package| package.methods.get(&call.export).map(|m| m.event_bytes))
                .unwrap_or(0)
        })
        .collect();
    let event_bytes = admit_event_bounds(&per_call, per_call.len())?;
    // The authority gate admission resolved for each node, read back
    // rather than re-derived: the report answers with the verdict
    // execution will judge, over the node's real bound inputs.
    let mut authority = Vec::with_capacity(admitted.manifest().nodes.len());
    for (index, node) in admitted.manifest().nodes.iter().enumerate() {
        let evidence = admitted.calls()[index].evidence.as_slice();
        let required = match admitted.calls()[index].requires.as_slice() {
            [] => Authority::Anyone,
            [rule] => authority_of(rule, evidence),
            // Several required rules conjoin: the threshold whose count
            // is its width, so the report says every one of them is
            // asked, and what each asks.
            rules => Authority::Threshold {
                count: u8::try_from(rules.len()).unwrap_or(u8::MAX),
                branches: rules
                    .iter()
                    .map(|rule| authority_of(rule, evidence))
                    .collect(),
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
    // encoding refuses fails here rather than at a display seam. The
    // authorities' own names — a signer, the badge a holder presents —
    // are walked however deep a threshold holds them, so `text` answers
    // for every address the report itself hands the caller.
    let mut named = BTreeMap::new();
    let mut authority_names = Vec::new();
    for required in &authority {
        required.authority.names(&mut authority_names);
    }
    let addresses = authority
        .iter()
        .map(|required| required.target)
        .chain(authority_names)
        .chain(subintents.iter().map(|record| record.signer.address()));
    for address in addresses {
        if let Entry::Vacant(slot) = named.entry(address) {
            slot.insert(address.to_text(network)?);
        }
    }

    Ok(Report {
        network: NetworkWord(network.to_owned()),
        admitted,
        composer,
        root_intent,
        authority,
        subintents,
        event_bytes,
        event_bytes_by_node: per_call,
        named,
    })
}
