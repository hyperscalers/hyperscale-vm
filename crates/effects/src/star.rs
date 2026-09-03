//! The star classifier: how a routed transaction's participants could
//! divide its execution.
//!
//! Standalone from the routing fold — nothing on the execution path
//! consumes the verdict yet, and the classification is a pure function
//! of the manifest, the metadata, admission's lowering and shard
//! placement, so it is asked where it is wanted rather than computed on
//! every `route()` call.
//!
//! The vocabulary — [`LegRole`], [`ValueEdge`], [`LegShape`] — is
//! [`hyperscale_vm_types`]'s, so the protocol carries the classifier's
//! own reading rather than a copy of it.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_types::{
    Address, CallTarget, LegRole, LegShape, MAX_CROSSINGS_PER_TX, SubintentHash, ValueEdge,
};

use crate::admission::{Admitted, NodeOrigin};
use crate::claim::Claim;
use crate::dsl::{Clause, ModeExpr};
use crate::hash::Hash32;
use crate::manifest::{Manifest, NodeInput};
use crate::records::ChainRecords;
use crate::route::ShardResolver;
use crate::signature::{MethodSignature, Totality};
use crate::types::{EdgeContent, ShardId};

/// A classified transaction: the star its shape implies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StarShape {
    /// Where each manifest node sits in the star, in node order, with
    /// the attesting nodes settled against placement.
    pub roles: Vec<LegRole>,
    /// The shards the core's nodes sit on. May be empty — see
    /// [`Self::decomposes`], which refuses that case.
    pub core: BTreeSet<ShardId>,
    /// How many value edges land on a shard other than their producer's.
    /// Each is one certificate entry, which is what bounds it.
    pub crossing_edges: u32,
}

/// Classify an admitted transaction into the star its shape implies.
///
/// # Errors
///
/// [`UnresolvedTarget`], on [`classify_roles`]'s terms.
pub fn classify(
    admitted: &Admitted,
    chain: &dyn ChainRecords,
    shards: &dyn ShardResolver,
) -> Result<StarShape, UnresolvedTarget> {
    Ok(star_at(&legs_of(admitted, chain)?, shards))
}

/// Each admitted node's placement-free shape, in node order.
///
/// Everything the envelope fixes about a node: its role, the edges it
/// consumes, the claims it presents, the owners it declares, and the
/// signed intent it came from. What placement adds is read off a
/// resolver at [`star_at`], and nothing here.
///
/// # Errors
///
/// [`UnresolvedTarget`], on [`classify_roles`]'s terms.
pub fn legs_of(
    admitted: &Admitted,
    chain: &dyn ChainRecords,
) -> Result<Vec<LegShape>, UnresolvedTarget> {
    let manifest = admitted.manifest();
    let roles = classify_roles(manifest, chain, &admitted.answered_at_admission())?;
    Ok(assemble(
        manifest,
        &roles,
        admitted.origins(),
        admitted.declares(),
    ))
}

/// Classify every manifest node into the star, before placement.
///
/// The leg tests are structural, and each is read off the manifest's own
/// edges and the method's declaration rather than off what a method is
/// named:
///
/// - An **inbound** leg takes no value edge, so nothing the core produces
///   can be among its arguments, and its only movement is one reserve.
/// - An **attesting** leg takes no value edge and moves nothing at all.
/// - An **outbound** leg's output feeds nothing and nothing about it can
///   refuse: the verified [`Totality::Total`] mark over its body, no
///   evidence asked of its caller, no declared bound on an edge it
///   consumes, and a frame admission alone answers.
///
/// Every other node is core, and so is every node the tests are unsure
/// about. That direction is the safe one: a node wrongly called core
/// costs the transaction a decomposition it could have had, while a leg
/// wrongly peeled off the core costs the atomicity the core exists for.
///
/// `answered` is [`Admitted::answered_at_admission`], in node order: the
/// outbound test is not a function of the manifest and its metadata
/// alone, because what a frame ends up carrying is a fact about the
/// injection. It stays fixed by the envelope forever all the same, since
/// presented records are envelope content. A node whose `answered` entry
/// is missing is core on the same rule.
///
/// # Errors
///
/// [`UnresolvedTarget`] where a node names a target this chain view
/// cannot resolve. Defaulting it to core would be the safe direction for
/// a resolvable-but-odd method and the wrong one here: it caches a role
/// derived from not having seen the package, and every replica derives
/// this locally, so two of them would disagree about the legs, the
/// crossings and therefore the kernel cells. The transaction waits for
/// the package instead.
pub fn classify_roles(
    manifest: &Manifest,
    chain: &dyn ChainRecords,
    answered: &[bool],
) -> Result<Vec<LegRole>, UnresolvedTarget> {
    let consumed: BTreeSet<u32> = manifest
        .nodes
        .iter()
        .flat_map(|node| &node.inputs)
        .filter_map(|input| match input {
            NodeInput::Edge { source, .. } => Some(*source),
            NodeInput::Literal(_) => None,
        })
        .collect();

    manifest
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let resolved = CallTarget::try_from(node.target)
                .ok()
                .and_then(|target| chain.instance(target))
                .and_then(|meta| chain.package(meta.package));
            let signature = resolved
                .as_ref()
                .and_then(|pkg| pkg.methods.get(&node.method));
            let Some(signature) = signature else {
                return Err(UnresolvedTarget { node: index });
            };
            let takes_no_edge = node
                .inputs
                .iter()
                .all(|input| matches!(input, NodeInput::Literal(_)));
            let unrefusable = answered.get(index).copied().unwrap_or(false)
                && is_unrefusable(signature, &node.inputs);
            let index = u32::try_from(index).unwrap_or(u32::MAX);

            Ok(if takes_no_edge && is_reservation_shaped(signature) {
                LegRole::Inbound
            } else if takes_no_edge && commits_nothing(signature) {
                LegRole::Attesting
            } else if !consumed.contains(&index) && unrefusable {
                LegRole::Outbound
            } else {
                LegRole::Core
            })
        })
        .collect()
}

/// A node naming a target this chain view cannot resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnresolvedTarget {
    /// Which node names it.
    pub node: usize,
}

/// Put one node's shape together from the pieces admission fixes.
///
/// A node with no origin or no declaration entry — a manifest built by
/// hand rather than admitted — gets an unsigned origin and declares its
/// own target, which is the ordinary case and the one every test that
/// says nothing else means.
fn assemble(
    manifest: &Manifest,
    roles: &[LegRole],
    origins: &[NodeOrigin],
    declares: Vec<Vec<Address>>,
) -> Vec<LegShape> {
    let mut declares = declares.into_iter();
    manifest
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let origin = origins.get(index).copied().unwrap_or_else(|| NodeOrigin {
                intent: SubintentHash(Hash32([0; 32])),
                local: u32::try_from(index).unwrap_or(u32::MAX),
                expiry_ms: 0,
            });
            LegShape {
                target: node.target,
                role: roles.get(index).copied().unwrap_or_default(),
                edges: node
                    .inputs
                    .iter()
                    .filter_map(|input| match input {
                        NodeInput::Edge {
                            source,
                            output,
                            content,
                            ..
                        } => Some(ValueEdge {
                            source: *source,
                            output: *output,
                            non_fungible: matches!(content, EdgeContent::NonFungible { .. }),
                        }),
                        NodeInput::Literal(_) => None,
                    })
                    .collect(),
                presents: node.evidence.iter().map(Claim::address).collect(),
                declares: declares.next().unwrap_or_else(|| vec![node.target]),
                intent: origin.intent,
                local: origin.local,
                expiry_ms: origin.expiry_ms,
            }
        })
        .collect()
}

/// Anchor a classification: settle the attesting nodes, and read the core
/// set and the crossing count off the placement.
///
/// The half a parent re-derives at each anchor. Everything in `legs` is
/// fixed by the envelope, and this is the only part a reshape can move.
#[must_use]
pub fn star_at(legs: &[LegShape], shards: &dyn ShardResolver) -> StarShape {
    let roles = settle_attesting(legs, shards);
    let core = roles
        .iter()
        .zip(legs)
        .filter(|(role, _)| **role == LegRole::Core)
        .map(|(_, node)| shards.shard_of(node.target))
        .collect();

    let mut crossing_edges: u32 = 0;
    for node in legs {
        let to = shards.shard_of(node.target);
        for edge in &node.edges {
            let from = legs
                .get(edge.source as usize)
                .map(|producer| shards.shard_of(producer.target));
            if from.is_some_and(|from| from != to) {
                crossing_edges = crossing_edges.saturating_add(1);
            }
        }
    }

    StarShape {
        roles,
        core,
        crossing_edges,
    }
}

/// Which write-free nodes stay legs, and which fall back into the core.
///
/// Two questions, both about placement, which is why this runs here and
/// not in [`classify_roles`].
///
/// **Its proof must stay home.** A node presenting what an attesting node
/// proved runs in a world where that node succeeded, and under
/// decomposition it learns that by running beside it. A consumer on
/// another shard would have to take the proof as an attested value, which
/// is a second crossing kind and not one this design builds — so the
/// attesting node goes back to the core, where every participant runs it.
///
/// Which node proved a claim is not on the shape — the manifest resolved
/// the evidence into its subject — so the match is by subject. A subject
/// that is some node's own target names that node; a badge or any other
/// subject no node is names whichever attesting node proved it, which is
/// not known, so it is taken to name every one of them. Over-flagging
/// sends a proof to the core that could have stayed home, which costs a
/// replication; under-flagging would run a gate against a proof its
/// prover never made.
///
/// **The core must have a bearer.** A core with no node in it names no
/// shard for a refusal, a departure or an absence to be taken against, so
/// there is nothing for a reclaim to be admitted on. Where nothing else
/// is in the core, every write-free node is — all of them, so which one
/// bears the verdict is never a pick.
fn settle_attesting(legs: &[LegShape], shards: &dyn ShardResolver) -> Vec<LegRole> {
    let mut settled: Vec<LegRole> = legs.iter().map(|node| node.role).collect();
    for (index, node) in legs.iter().enumerate() {
        if settled.get(index) != Some(&LegRole::Attesting) {
            continue;
        }
        let here = shards.shard_of(node.target);
        let names_me = |subject: &Address| {
            *subject == node.target || !legs.iter().any(|other| other.target == *subject)
        };
        let stays_home = legs.iter().all(|other| {
            shards.shard_of(other.target) == here || !other.presents.iter().any(names_me)
        });
        if !stays_home {
            settled[index] = LegRole::Core;
        }
    }
    if !settled.contains(&LegRole::Core) {
        for role in &mut settled {
            if *role == LegRole::Attesting {
                *role = LegRole::Core;
            }
        }
    }
    settled
}

impl StarShape {
    /// Whether running this transaction's legs where their state lives
    /// differs from running the whole of it on the core's shards.
    ///
    /// Every conjunct refuses rather than admits —
    /// running whole is always correct, so an unsure answer takes it.
    /// `legs` is the shape this star was read off, and `owners` the
    /// parties the transaction's routing declares beyond any node's
    /// frame: the fee payer and every signer.
    #[must_use]
    pub fn decomposes(
        &self,
        legs: &[LegShape],
        owners: &[Address],
        shards: &dyn ShardResolver,
    ) -> bool {
        self.core_bears_a_verdict()
            && self.a_leg_sits_off_the_core(legs, shards)
            && self.crossings_fit()
            && Self::every_declared_owner_participates(legs, shards)
            && Self::every_route_owner_participates(legs, owners, shards)
            && self.every_node_declares_inside_its_scope(legs, shards)
            && Self::every_edge_has_one_consumer(legs)
            && self.no_named_instance_touches_a_leg(legs)
    }

    /// A decomposed member judges only what its own execution scope
    /// covers, so a declaration reaching a shard that runs nothing would
    /// leave that target judged by nobody, where a whole execution judged
    /// it everywhere. Running whole is always correct, so a shape
    /// reaching past its own participants takes that.
    ///
    /// The case that makes this real is a reaching access rather than a
    /// deposit: a reach puts the read under the reached party's owner,
    /// who need not be any node's target — where a movement's owner is
    /// the moving party and usually is one, so a reader checking only
    /// deposits concludes this cannot happen.
    fn every_declared_owner_participates(legs: &[LegShape], shards: &dyn ShardResolver) -> bool {
        let participants: BTreeSet<ShardId> = legs
            .iter()
            .map(|node| shards.shard_of(node.target))
            .collect();
        legs.iter()
            .flat_map(|node| &node.declares)
            .all(|owner| participants.contains(&shards.shard_of(*owner)))
    }

    /// Every party the routing declares beyond any node's frame — the
    /// fee payer, whose vault the reservation and the burn reach, and
    /// every signer, whose nullifier a bound subintent writes — sits on
    /// a shard that runs a member, so some member's scope covers it.
    ///
    /// A payer whose account no node targets is a routing participant
    /// that runs nothing: its shard would freeze divided, compose a
    /// member and find no plan for it, and attest a refusal with the
    /// price apart while the core committed. A signer with no node on
    /// their shard would have their nullifier written by whichever
    /// member happened to run there, after the core committed or never.
    /// Running whole provisions the vault and writes the nullifier where
    /// a whole execution always did.
    fn every_route_owner_participates(
        legs: &[LegShape],
        owners: &[Address],
        shards: &dyn ShardResolver,
    ) -> bool {
        let participants: BTreeSet<ShardId> = legs
            .iter()
            .map(|node| shards.shard_of(node.target))
            .collect();
        owners
            .iter()
            .all(|owner| participants.contains(&shards.shard_of(*owner)))
    }

    /// Every target a node declares sits inside the scope of the member
    /// that runs it: its own shard for a leg, the core set for a core
    /// node.
    ///
    /// Participation is not enough. A target owned by *some* participant
    /// is judged by that participant, but the node that declared it runs
    /// elsewhere, against a store that never held the cell — a read there
    /// answers absent, a reservation there is one nobody held for it, and
    /// neither says anything. Running whole provisions everything to
    /// everyone, which is what makes such a shape correct undivided.
    fn every_node_declares_inside_its_scope(
        &self,
        legs: &[LegShape],
        shards: &dyn ShardResolver,
    ) -> bool {
        self.roles.iter().zip(legs).all(|(role, node)| {
            let home = shards.shard_of(node.target);
            node.declares.iter().all(|owner| {
                let at = shards.shard_of(*owner);
                match role {
                    LegRole::Core => self.core.contains(&at),
                    LegRole::Inbound | LegRole::Outbound | LegRole::Attesting => at == home,
                }
            })
        })
    }

    /// A reservation-shaped source feeding a total sink has no core node
    /// at all, and nothing then names a shard for a refusal, a departure
    /// or an absence to be taken against. An escrow issued under such a
    /// shape would have no reclaim path.
    fn core_bears_a_verdict(&self) -> bool {
        !self.core.is_empty()
    }

    /// Otherwise the whole transaction is already on the core's shards,
    /// and dividing it names the same execution.
    fn a_leg_sits_off_the_core(&self, legs: &[LegShape], shards: &dyn ShardResolver) -> bool {
        self.roles.iter().zip(legs).any(|(role, node)| {
            *role != LegRole::Core && !self.core.contains(&shards.shard_of(node.target))
        })
    }

    /// Each crossing is a fixed-width entry in the receipt leaf, so a
    /// shape carrying more than one outcome can encode is one no
    /// participant could state a verdict for.
    const fn crossings_fit(&self) -> bool {
        self.crossing_edges as usize <= MAX_CROSSINGS_PER_TX
    }

    /// A claim cell is keyed by the consuming node's target, so two sinks
    /// consuming one output write two different claim cells and each
    /// credits the full amount. Today one participant runs both consumers
    /// and session bucket linearity refuses the second; decomposition puts
    /// them in two sessions on two shards and removes the only witness,
    /// while each side's conservation fold still balances locally.
    ///
    /// Running whole restores the witness, and a manifest with two
    /// consumers of one output is a double spend that aborts there
    /// anyway — so this costs nothing real.
    fn every_edge_has_one_consumer(legs: &[LegShape]) -> bool {
        let mut consumers: BTreeMap<(u32, u32), u32> = BTreeMap::new();
        for node in legs {
            for edge in &node.edges {
                *consumers.entry((edge.source, edge.output)).or_default() += 1;
            }
        }
        consumers.values().all(|count| *count <= 1)
    }

    /// The escrow attestation is linear over amounts and blind to
    /// identity, so a fabricated non-fungible credit would arrive with a
    /// delta its producer's history supports. The test is over legs
    /// alone: a core's participants agree by unanimity rather than by
    /// attested value, so nothing inside one is exposed to it.
    fn no_named_instance_touches_a_leg(&self, legs: &[LegShape]) -> bool {
        let is_leg = |index: usize| {
            self.roles
                .get(index)
                .is_some_and(|role| *role != LegRole::Core)
        };
        legs.iter().enumerate().all(|(index, node)| {
            node.edges
                .iter()
                .all(|edge| !edge.non_fungible || !(is_leg(index) || is_leg(edge.source as usize)))
        })
    }
}

/// Whether a signature is the shape an inbound leg has to be: one
/// conditional decrement of its own, and no other movement beside it.
///
/// The reserve is what makes the leg's refusal local — the amount is
/// judged where the funds live, and a refusal there releases rather than
/// aborting the core.
///
/// The reserve has to be the *whole* job, and that is what INV-LL-3 rests
/// on. A method declaring one reserve, an exclusive write on a second
/// cell and a delta on a third would commit those two before the core
/// has a verdict, where a reclaim restores the escrowed amount and
/// nothing else — nothing stores an inverse of the rest. Asking that
/// every clause either moves nothing or is that one reserve says so
/// directly for the clauses; an issuance or a destruction is a movement
/// no clause names, and a second output is one an issuance produced, so
/// the signature is held to none of either and to the one output the
/// reserve yields. A reserve beside a mint would cross two values one
/// origin cannot take both of back, and a reserve beside a burn commits
/// the burn before any verdict.
fn is_reservation_shaped(signature: &MethodSignature) -> bool {
    if !signature.issues.is_empty()
        || !signature.destroys.is_empty()
        || signature.outputs.len() != 1
    {
        return false;
    }
    let mut reserves = 0;
    for clause in signature.effects.iter().flat_map(Clause::effects) {
        let Clause::Effect { mode, reach, .. } = clause else {
            continue;
        };
        if mode.moves().is_none() {
            continue;
        }
        if matches!(mode, ModeExpr::Reserve(_)) && reach.is_none() {
            reserves += 1;
        } else {
            return false;
        }
    }
    reserves == 1
}

/// Whether this method commits nothing at all.
///
/// Every declared access is a read, no value edge leaves, and nothing
/// is issued or destroyed — which is what makes such a node free of the
/// atomicity the core covers, and so free to run in its own shard's leg.
/// `moves()` is `None` for exactly [`ModeExpr::Read`], so this reads as
/// no writes rather than only as no value movement, which is what
/// INV-LL-3 needs of it.
fn commits_nothing(signature: &MethodSignature) -> bool {
    signature.outputs.is_empty()
        && signature.issues.is_empty()
        && signature.destroys.is_empty()
        && signature
            .effects
            .iter()
            .flat_map(Clause::effects)
            .all(|clause| match clause {
                Clause::Effect { mode, .. } => mode.moves().is_none(),
                _ => true,
            })
}

/// Whether nothing about this call can refuse before its body runs.
///
/// [`Totality::Total`] covers the body and nothing else, and two
/// refusals run ahead of it: the method's own authority gate, which
/// nothing stops a total method carrying, and the signed bounds on the
/// edges it consumes, which a producer returning too little fails
/// whatever the callee would have done. A declared bound therefore costs
/// the decomposition rather than the atomicity.
fn is_unrefusable(signature: &MethodSignature, inputs: &[NodeInput]) -> bool {
    signature.totality == Totality::Total
        && !signature.requires_evidence()
        && inputs.iter().all(|input| match input {
            NodeInput::Edge { bounds, .. } => bounds.admit_anything(),
            NodeInput::Literal(_) => true,
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_vm_types::{MAX_CROSSINGS_PER_TX, Moves, ResourceAddr};

    use super::{Address, LegRole, LegShape, StarShape, assemble, classify_roles, star_at};
    use crate::claim::Claim;
    use crate::dsl::{Clause, Expr, ModeExpr};
    use crate::hash::TestHasher;
    use crate::manifest::{Bounds, Manifest, Node, NodeInput};
    use crate::metadata::PackageMetadata;
    use crate::records::{ChainRecords, Records};
    use crate::resource::{GrantsExpr, ResourceKind};
    use crate::route::ShardResolver;
    use crate::rule::{RuleExpr, RuleLeaf};
    use crate::signature::{Issuance, Issued, MethodSignature, Totality};
    use crate::test_worlds::{
        instance_of, issued_by, meta_of, method, payer_payee_world, pkg, resolver, self_point,
        star_world,
    };
    use crate::types::{EdgeContent, SlotId, Value};

    /// Every frame answered by admission alone.
    ///
    /// The hand-built manifests here carry no injected entry and no
    /// stored gate, so this states the fixture's own premise rather than
    /// standing in for admission — a test about the totality half says so
    /// where a permissive default would have hidden it.
    fn answered(manifest: &Manifest) -> Vec<bool> {
        vec![true; manifest.nodes.len()]
    }

    /// The legs a hand-built manifest implies under `answered`, each
    /// declaring exactly its own target — the ordinary case, so a test
    /// about anything else states its own declaration instead.
    fn legs_under(manifest: &Manifest, chain: &Records, answered: &[bool]) -> Vec<LegShape> {
        let roles = classify_roles(manifest, chain, answered).expect("targets resolve");
        assemble(manifest, &roles, &[], Vec::new())
    }

    /// The legs a hand-built manifest implies, every frame answered by
    /// admission alone.
    fn legs(manifest: &Manifest, chain: &Records) -> Vec<LegShape> {
        legs_under(manifest, chain, &answered(manifest))
    }

    /// The star and the legs it was read off, since the predicate needs
    /// both and no test wants to spell the pair twice.
    fn star_and_shape(manifest: &Manifest, chain: &Records) -> (StarShape, Vec<LegShape>) {
        let legs = legs(manifest, chain);
        (star_at(&legs, &resolver()), legs)
    }

    /// Whether the shape decomposes, over a declaration reaching exactly
    /// its own nodes and a routing declaring nobody beyond them.
    fn decomposes(manifest: &Manifest, chain: &Records) -> bool {
        let (star, legs) = star_and_shape(manifest, chain);
        star.decomposes(&legs, &[], &resolver())
    }

    /// The star world with one method's signature replaced.
    ///
    /// Rebuilt rather than re-published: a package hash is a content
    /// address, so a second publish under one hash keeps the first
    /// record and a test that mutated in place would assert against the
    /// package it meant to replace.
    fn star_world_with(
        package: &str,
        method: &str,
        signature: &MethodSignature,
    ) -> (Records, Manifest) {
        let (base, manifest) = star_world(Totality::Total);
        let mut chain = Records::new();
        for name in ["vault", "venue", "sink"] {
            let mut metadata =
                (*base.package(pkg(name)).expect("the fixture published it")).clone();
            if name == package {
                metadata.methods.insert(method.into(), signature.clone());
            }
            chain.packages.publish_unchecked(pkg(name), metadata);
            chain.instances.create(&TestHasher, meta_of(name));
        }
        (chain, manifest)
    }

    /// One instance calling itself: nothing to decompose.
    fn solo_world() -> (Records, Manifest) {
        let mut chain = Records::new();
        let mut solo = PackageMetadata::default();
        solo.methods.insert(
            "act".into(),
            method(vec![self_point(
                SlotId(1),
                ModeExpr::Delta { moves: Moves::Both },
            )]),
        );
        chain.packages.publish_unchecked(pkg("solo"), solo);
        chain.instances.create(&TestHasher, meta_of("solo"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("solo").into(),
                method: "act".into(),
                inputs: vec![],
                evidence: Vec::new(),
            }],
        };
        (chain, manifest)
    }

    /// A call that stays on one shard crosses nothing, so a staged
    /// execution of it would pay for no boundary at all.
    #[test]
    fn a_single_shard_transaction_alternates_zero_times() {
        let (chain, manifest) = solo_world();
        let star = star_at(&legs(&manifest, &chain), &resolver());
        assert_eq!(star.crossing_edges, 0);
    }

    /// A call reaching one instance on another shard crosses once. The
    /// depth counts the crossing rather than the shards, which is the
    /// distinction the whole quantity turns on — a chain returning to a
    /// shard it already visited has crossed twice, not once.
    #[test]
    fn a_call_to_another_shard_alternates_once() {
        let (chain, manifest) = payer_payee_world();
        assert_ne!(
            resolver().shard_of(instance_of("payer").into()),
            resolver().shard_of(instance_of("payee").into()),
            "the fixture has to straddle, or the depth below proves nothing",
        );
        let star = star_at(&legs(&manifest, &chain), &resolver());
        assert_eq!(star.crossing_edges, 1);
    }

    /// A value edge is a dependency like a call is: the consumer cannot
    /// run until the producer's output exists, so a consumer on another
    /// shard is a boundary even though neither node calls the other.
    #[test]
    fn a_value_edge_across_shards_alternates_once() {
        let mut chain = Records::new();
        let mut producing = PackageMetadata::default();
        producing.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
                outputs: vec![Expr::SelfAddr],
                effects: vec![self_point(
                    SlotId(1),
                    ModeExpr::Delta { moves: Moves::Both },
                )],
                ..MethodSignature::default()
            },
        );
        let mut consuming = PackageMetadata::default();
        consuming.methods.insert(
            "take".into(),
            method(vec![self_point(
                SlotId(2),
                ModeExpr::Delta { moves: Moves::Both },
            )]),
        );
        chain.packages.publish_unchecked(pkg("producer"), producing);
        chain.packages.publish_unchecked(pkg("consumer"), consuming);
        chain.instances.create(&TestHasher, meta_of("producer"));
        chain.instances.create(&TestHasher, meta_of("consumer"));
        assert_ne!(
            resolver().shard_of(instance_of("producer").into()),
            resolver().shard_of(instance_of("consumer").into()),
            "the fixture has to straddle, or the depth below proves nothing",
        );

        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("producer").into(),
                    method: "make".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                },
                Node {
                    target: instance_of("consumer").into(),
                    method: "take".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 0,
                        resource: issued_by("producer"),
                        content: EdgeContent::Fungible,
                        bounds: Bounds::default(),
                    }],
                    evidence: Vec::new(),
                },
            ],
        };

        let star = star_at(&legs(&manifest, &chain), &resolver());
        assert_eq!(star.crossing_edges, 1);
    }

    /// The reservation-shaped source is the inbound leg: nothing the core
    /// produces reaches its arguments, so it can run first, and the
    /// reserve is what lets its refusal release rather than abort.
    #[test]
    fn a_reservation_shaped_source_is_an_inbound_leg() {
        let (chain, manifest) = star_world(Totality::Fallible);
        let star = star_at(&legs(&manifest, &chain), &resolver());
        assert_eq!(star.roles[0], LegRole::Inbound);
        assert_eq!(star.roles[1], LegRole::Core, "the venue is the core");
    }

    /// A sink whose method carries the verified mark is the outbound leg.
    /// Without the mark the same node is core — the shape alone never
    /// earns it, because what the core needs is the guarantee that
    /// nothing comes back, and only the checker can give that.
    #[test]
    fn only_a_marked_sink_is_an_outbound_leg() {
        for (totality, expected) in [
            (Totality::Fallible, LegRole::Core),
            (Totality::Infallible, LegRole::Core),
            (Totality::Total, LegRole::Outbound),
        ] {
            let (chain, manifest) = star_world(totality);
            let star = star_at(&legs(&manifest, &chain), &resolver());
            assert_eq!(
                star.roles[2], expected,
                "a {totality:?} sink should be {expected:?}",
            );
        }
    }

    /// Taking a value edge is what disqualifies an inbound leg, whatever
    /// its shape: an argument the core produced cannot be available
    /// before the core runs, which is the whole of L3's test.
    #[test]
    fn a_reservation_fed_by_the_core_joins_it() {
        let (chain, _) = star_world(Totality::Fallible);
        // The venue first, and the same reservation-shaped method after
        // it — its amount now the venue's output rather than a literal.
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("venue").into(),
                    method: "swap".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                },
                Node {
                    target: instance_of("vault").into(),
                    method: "withdraw".into(),
                    // The amount stays a literal so the reserve still
                    // evaluates — what disqualifies the leg is the edge
                    // beside it, not what the reserve reads.
                    inputs: vec![
                        NodeInput::Literal(Value::U128(5)),
                        NodeInput::Edge {
                            source: 0,
                            output: 0,
                            resource: issued_by("venue"),
                            content: EdgeContent::Fungible,
                            bounds: Bounds::default(),
                        },
                    ],
                    evidence: Vec::new(),
                },
            ],
        };

        let star = star_at(&legs(&manifest, &chain), &resolver());
        assert_eq!(
            star.roles[1],
            LegRole::Core,
            "a reserve fed by an edge is not core-independent",
        );
    }

    /// A gate on a total sink is a refusal the mark does not cover: the
    /// checker verified the body, and the gate runs before it. A core
    /// waiting on such a leg was told a verdict could not come from a
    /// node that can still produce one.
    #[test]
    fn a_gated_total_sink_is_core() {
        let (chain, manifest) = star_world_with(
            "sink",
            "deposit",
            &MethodSignature {
                totality: Totality::Total,
                effects: vec![
                    self_point(SlotId(3), ModeExpr::Delta { moves: Moves::Both }),
                    Clause::Requires {
                        guard: None,
                        rule: RuleExpr::Require(RuleLeaf::Claim(Expr::SelfAddr)),
                    },
                ],
                ..MethodSignature::default()
            },
        );

        let star = star_at(&legs(&manifest, &chain), &resolver());
        assert_eq!(
            star.roles[2],
            LegRole::Core,
            "a gated sink can still refuse"
        );
    }

    /// A signed bound on the edge a sink consumes is refused by the
    /// manifest before the callee is reached, so the mark over its body
    /// says nothing about it. The bound costs the decomposition, never
    /// the atomicity.
    #[test]
    fn a_sink_behind_a_declared_bound_is_core() {
        let (chain, manifest) = star_world(Totality::Total);
        let mut bounded = manifest.clone();
        let NodeInput::Edge { bounds, .. } = &mut bounded.nodes[2].inputs[0] else {
            panic!("the sink consumes the venue's edge");
        };
        bounds.min = Some(1);

        assert_eq!(
            star_at(&legs(&manifest, &chain), &resolver()).roles[2],
            LegRole::Outbound,
            "the fixture has to be outbound unbounded, or the verdict below proves nothing",
        );
        assert_eq!(
            star_at(&legs(&bounded, &chain), &resolver()).roles[2],
            LegRole::Core,
        );
    }

    /// A frame carrying a verdict later than admission is one an outbound
    /// leg may not have: it materializes on its own shard after the core
    /// committed, so the refusal lands on a caller that already did.
    #[test]
    fn a_sink_judged_later_than_admission_is_core() {
        let (chain, manifest) = star_world(Totality::Total);
        let mut later = answered(&manifest);
        later[2] = false;

        assert_eq!(
            star_at(&legs(&manifest, &chain), &resolver()).roles[2],
            LegRole::Outbound,
        );
        assert_eq!(
            star_at(&legs_under(&manifest, &chain, &later), &resolver()).roles[2],
            LegRole::Core,
        );
    }

    /// A reserve beside another movement is not a reservation-shaped leg.
    /// The second movement commits before the core has a verdict and no
    /// reclaim restores it — which is INV-LL-3, and it is what the leg
    /// test has to say rather than imply.
    #[test]
    fn a_reserve_beside_another_movement_is_not_inbound() {
        let (chain, manifest) = star_world_with(
            "vault",
            "withdraw",
            &MethodSignature {
                outputs: vec![Expr::SelfResource {
                    kind: ResourceKind::Fungible,
                    material: vec![],
                    grants: GrantsExpr::new(),
                }],
                effects: vec![
                    self_point(SlotId(1), ModeExpr::Reserve(Expr::Arg(0))),
                    self_point(SlotId(4), ModeExpr::Write { moves: Moves::Both }),
                ],
                ..MethodSignature::default()
            },
        );

        let star = star_at(&legs(&manifest, &chain), &resolver());
        assert_eq!(star.roles[0], LegRole::Core);
    }

    /// An issuance is a movement no clause names, so a reserve beside a
    /// mint — two values crossing, one origin — or beside a burn, which
    /// commits before any verdict, is not inbound either.
    #[test]
    fn a_reserve_beside_an_issuance_is_not_inbound() {
        let output = || Expr::SelfResource {
            kind: ResourceKind::Fungible,
            material: vec![],
            grants: GrantsExpr::new(),
        };
        for signature in [
            MethodSignature {
                outputs: vec![output(), output()],
                effects: vec![self_point(SlotId(1), ModeExpr::Reserve(Expr::Arg(0)))],
                issues: vec![Issuance {
                    mark: vec![],
                    kind: ResourceKind::Fungible,
                    direction: Issued::Minted,
                    grants: GrantsExpr::new(),
                }],
                ..MethodSignature::default()
            },
            MethodSignature {
                outputs: vec![output()],
                effects: vec![self_point(SlotId(1), ModeExpr::Reserve(Expr::Arg(0)))],
                destroys: vec![0],
                ..MethodSignature::default()
            },
        ] {
            let (chain, manifest) = star_world_with("vault", "withdraw", &signature);
            let star = star_at(&legs(&manifest, &chain), &resolver());
            assert_eq!(star.roles[0], LegRole::Core);
        }
    }

    /// A clause that moves nothing sits beside the reserve without
    /// disqualifying it — the test is about what commits, and a read
    /// commits nothing.
    #[test]
    fn a_reserve_beside_a_read_is_still_inbound() {
        let (chain, manifest) = star_world_with(
            "vault",
            "withdraw",
            &MethodSignature {
                outputs: vec![Expr::SelfResource {
                    kind: ResourceKind::Fungible,
                    material: vec![],
                    grants: GrantsExpr::new(),
                }],
                effects: vec![
                    self_point(SlotId(1), ModeExpr::Reserve(Expr::Arg(0))),
                    self_point(SlotId(4), ModeExpr::Read),
                ],
                ..MethodSignature::default()
            },
        );

        let star = star_at(&legs(&manifest, &chain), &resolver());
        assert_eq!(star.roles[0], LegRole::Inbound);
    }

    /// The world the write-free tests share: an account that proves its
    /// own identity and withdraws under it, and a total sink elsewhere.
    ///
    /// One instance for both nodes, which is what an account is — a
    /// sign-in reads the authority cell the withdrawal is gated on, and
    /// they are the same party's cells by construction.
    fn signed_world() -> (Records, Manifest) {
        let (base, _) = star_world(Totality::Total);
        let mut chain = Records::new();
        for name in ["venue", "sink"] {
            let metadata = (*base.package(pkg(name)).expect("the fixture published it")).clone();
            chain.packages.publish_unchecked(pkg(name), metadata);
            chain.instances.create(&TestHasher, meta_of(name));
        }
        let mut account = (*base.package(pkg("vault")).expect("published")).clone();
        account.methods.insert(
            "authorize".into(),
            MethodSignature {
                effects: vec![self_point(SlotId(9), ModeExpr::Read)],
                ..MethodSignature::default()
            },
        );
        chain.packages.publish_unchecked(pkg("vault"), account);
        chain.instances.create(&TestHasher, meta_of("vault"));

        let account: Address = instance_of("vault").into();
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: account,
                    method: "authorize".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                },
                Node {
                    target: account,
                    method: "withdraw".into(),
                    inputs: vec![NodeInput::Literal(Value::U128(5))],
                    evidence: vec![Claim::of_subject(account)],
                },
                Node {
                    target: instance_of("sink").into(),
                    method: "deposit".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 1,
                        output: 0,
                        resource: issued_by("vault"),
                        content: EdgeContent::Fungible,
                        bounds: Bounds::default(),
                    }],
                    evidence: Vec::new(),
                },
            ],
        };
        (chain, manifest)
    }

    /// The same world with the venue between the withdrawal and the sink,
    /// so the core has a node of its own.
    fn signed_world_with_a_venue() -> (Records, Manifest) {
        let (chain, mut manifest) = signed_world();
        manifest.nodes.insert(
            2,
            Node {
                target: instance_of("venue").into(),
                method: "swap".into(),
                inputs: vec![NodeInput::Edge {
                    source: 1,
                    output: 0,
                    resource: issued_by("vault"),
                    content: EdgeContent::Fungible,
                    bounds: Bounds::default(),
                }],
                evidence: Vec::new(),
            },
        );
        manifest.nodes[3].inputs = vec![NodeInput::Edge {
            source: 2,
            output: 0,
            resource: issued_by("venue"),
            content: EdgeContent::Fungible,
            bounds: Bounds::default(),
        }];
        (chain, manifest)
    }

    /// A node that only reads and proves commits nothing, so it bears no
    /// part of the atomicity the core covers and runs in its own shard's
    /// leg.
    #[test]
    fn a_write_free_source_is_attesting() {
        let (chain, manifest) = signed_world();
        let roles = classify_roles(&manifest, &chain, &answered(&manifest)).expect("resolve");
        assert_eq!(roles[0], LegRole::Attesting);
        assert_eq!(roles[1], LegRole::Inbound);
        assert_eq!(roles[2], LegRole::Outbound);
    }

    /// The core has to have somebody in it, and where the write-free node
    /// is the only candidate it is the one — so the shape below is core
    /// after the anchoring even though the role before it was not.
    #[test]
    fn a_write_free_source_bears_the_verdict_where_nothing_else_does() {
        let (chain, manifest) = signed_world();
        let (star, _) = star_and_shape(&manifest, &chain);
        assert_eq!(
            star.roles[0],
            LegRole::Core,
            "nothing else is in the core, so the sign-in is",
        );
        assert_eq!(star.core.len(), 1);
        assert!(decomposes(&manifest, &chain), "the sink is off the core");
    }

    /// With a real core beside it, the write-free node is a leg and the
    /// core is the core alone — which is what keeps a venue's shard from
    /// dragging every payer's shard in with it.
    #[test]
    fn a_write_free_source_leaves_a_core_that_has_one() {
        let (chain, manifest) = signed_world_with_a_venue();
        let (star, _) = star_and_shape(&manifest, &chain);
        assert_eq!(
            star.roles[0],
            LegRole::Attesting,
            "the venue bears the verdict"
        );
        assert_eq!(
            star.core,
            BTreeSet::from([resolver().shard_of(instance_of("venue").into())]),
            "and the core is the venue's shard alone",
        );
        assert!(decomposes(&manifest, &chain));
    }

    /// A proof consumed off its prover's shard would have to arrive as an
    /// attested value, which is a crossing kind this design does not
    /// build — so the prover goes back into the core, where every
    /// participant runs it.
    #[test]
    fn a_write_free_source_whose_proof_travels_is_core() {
        let (chain, mut manifest) = signed_world_with_a_venue();
        let account: Address = instance_of("vault").into();
        assert_ne!(
            resolver().shard_of(account),
            resolver().shard_of(instance_of("venue").into()),
            "the fixture has to straddle, or the verdict below proves nothing",
        );
        assert_eq!(
            star_and_shape(&manifest, &chain).0.roles[0],
            LegRole::Attesting,
            "and it has to start as a leg, or the verdict below proves nothing",
        );

        // The venue now speaks on the account's claim, from another shard.
        manifest.nodes[2].evidence = vec![Claim::of_subject(account)];

        let (star, _) = star_and_shape(&manifest, &chain);
        assert_eq!(star.roles[0], LegRole::Core);
    }

    /// A claim about a badge names no node's target, so which attesting
    /// node proved it is not on the shape. Presented from another shard,
    /// it sends every attesting node to the core — the over-flagging
    /// direction — rather than running a gate against a proof its prover
    /// never made.
    #[test]
    fn a_badge_claim_presented_elsewhere_sends_its_prover_to_the_core() {
        let (chain, mut manifest) = signed_world_with_a_venue();
        assert_eq!(
            star_and_shape(&manifest, &chain).0.roles[0],
            LegRole::Attesting,
            "the fixture has to start as a leg, or the verdict below proves nothing",
        );

        // A badge: a subject no node of the manifest is.
        let badge: Address = ResourceAddr::new([0xB4; 31]).into();
        assert!(
            !manifest.nodes.iter().any(|node| node.target == badge),
            "the badge has to be nobody's target, or the verdict below proves nothing",
        );
        manifest.nodes[2].evidence = vec![Claim::of_subject(badge)];
        let (star, _) = star_and_shape(&manifest, &chain);
        assert_eq!(star.roles[0], LegRole::Core);

        // Presented beside the prover, it stays home.
        manifest.nodes[2].evidence = Vec::new();
        manifest.nodes[1].evidence = vec![Claim::of_subject(badge)];
        let (star, _) = star_and_shape(&manifest, &chain);
        assert_eq!(star.roles[0], LegRole::Attesting);
    }

    /// A declaration reaching a party that runs nothing would leave that
    /// target judged by nobody, where a whole execution judged it
    /// everywhere.
    #[test]
    fn a_declaration_reaching_a_non_participant_does_not_decompose() {
        let (chain, manifest) = star_world(Totality::Total);
        let (star, mut legs) = star_and_shape(&manifest, &chain);
        assert!(star.decomposes(&legs, &[], &resolver()));

        legs[0].declares.push(instance_of("stranger").into());
        assert!(!star.decomposes(&legs, &[], &resolver()));
    }

    /// A party the routing declares beyond any node — a sponsored payer,
    /// a signer with no node of their own — has to sit on a shard some
    /// member runs on, or the shape runs whole: divided, that shard would
    /// compose a member with nothing to run and refuse while the core
    /// committed.
    #[test]
    fn a_route_owner_off_every_participant_does_not_decompose() {
        let (chain, manifest) = star_world(Totality::Total);
        let (star, legs) = star_and_shape(&manifest, &chain);
        let participant = legs[0].target;
        assert!(star.decomposes(&legs, &[participant], &resolver()));

        let stranger: Address = instance_of("stranger").into();
        assert!(!star.decomposes(&legs, &[stranger], &resolver()));
        assert!(!star.decomposes(&legs, &[participant, stranger], &resolver()));
    }

    /// A target owned by a participant is judged there — and if the node
    /// that declared it runs somewhere else, it runs against a store that
    /// never held the cell. So a node's declaration has to sit inside the
    /// scope of the member running it, which is stricter than every owner
    /// being some participant.
    #[test]
    fn a_node_declaring_past_its_own_scope_does_not_decompose() {
        let (chain, manifest) = star_world(Totality::Total);
        let (star, mut legs) = star_and_shape(&manifest, &chain);
        assert!(star.decomposes(&legs, &[], &resolver()));

        let (leg, core) = star.roles.iter().enumerate().fold(
            (None, None),
            |(leg, core), (index, role)| match role {
                LegRole::Core => (leg, core.or(Some(index))),
                _ => (leg.or(Some(index)), core),
            },
        );
        let (leg, core) = (leg.expect("a leg"), core.expect("a core"));
        assert_ne!(
            resolver().shard_of(legs[leg].target),
            resolver().shard_of(legs[core].target),
            "the leg has to sit off the core, or the verdict below proves nothing",
        );

        // Every owner is still a participant's; only the attribution
        // moved, and that is what refuses it.
        let reached = legs[core].target;
        legs[leg].declares.push(reached);
        assert!(!star.decomposes(&legs, &[], &resolver()));
    }

    /// A target this chain view cannot resolve fails derivation rather
    /// than defaulting to core: every replica derives this locally, so a
    /// role read off not having seen the package is a divergence waiting
    /// for the package to arrive.
    #[test]
    fn an_unresolvable_target_fails_derivation() {
        let (chain, mut manifest) = solo_world();
        manifest.nodes[0].method = "absent".into();
        assert_eq!(
            classify_roles(&manifest, &chain, &answered(&manifest)),
            Err(super::UnresolvedTarget { node: 0 }),
        );
    }

    /// Everything on one shard means one participant, so the two
    /// executions name the same thing and the verdict is the one claiming
    /// less.
    #[test]
    fn a_single_shard_transaction_does_not_decompose() {
        let (chain, manifest) = solo_world();
        let (star, _) = star_and_shape(&manifest, &chain);
        assert_eq!(star.core.len(), 1);
        assert!(!decomposes(&manifest, &chain));
    }

    /// A leg off the core's shard is the whole of what decomposition
    /// buys, so a shape with one takes it.
    #[test]
    fn a_leg_off_the_core_decomposes() {
        let (chain, manifest) = star_world(Totality::Total);
        let (star, _) = star_and_shape(&manifest, &chain);
        assert_eq!(star.core.len(), 1, "the venue is the whole core");
        assert!(decomposes(&manifest, &chain));
    }

    /// A leg carrying named instances runs whole: the escrow attestation
    /// counts amounts and cannot see which id moved, so nothing bounds a
    /// fabricated one.
    #[test]
    fn a_leg_moving_named_instances_does_not_decompose() {
        let (chain, manifest) = star_world(Totality::Total);
        assert!(decomposes(&manifest, &chain));

        // The identical shape, with the inbound leg's value now named.
        let mut named = manifest;
        named.nodes[1].inputs = vec![NodeInput::Edge {
            source: 0,
            output: 0,
            resource: issued_by("vault"),
            content: EdgeContent::NonFungible { ids: vec![7] },
            bounds: Bounds::default(),
        }];
        assert!(!decomposes(&named, &chain));
    }

    /// Two sinks reading one output write two claim cells on two shards,
    /// each crediting the whole amount, and the session that catches the
    /// double take is exactly what decomposition removes. Running whole
    /// restores it — where the manifest is a double spend that aborts
    /// anyway.
    #[test]
    fn a_value_edge_with_two_consumers_does_not_decompose() {
        let (chain, manifest) = star_world(Totality::Total);
        assert!(decomposes(&manifest, &chain));

        let mut shared = manifest;
        shared.nodes[2].inputs = vec![NodeInput::Edge {
            source: 0,
            output: 0,
            resource: issued_by("vault"),
            content: EdgeContent::Fungible,
            bounds: Bounds::default(),
        }];
        assert!(
            !decomposes(&shared, &chain),
            "the vault's one output now feeds the venue and the sink",
        );
    }

    /// Past the cap a shape carries more crossings than one outcome can
    /// state a verdict for, so no participant could encode one.
    #[test]
    fn a_shape_past_the_crossing_cap_does_not_decompose() {
        let (chain, manifest) = star_world(Totality::Total);
        let (mut star, legs) = star_and_shape(&manifest, &chain);
        assert!(star.decomposes(&legs, &[], &resolver()));

        star.crossing_edges = u32::try_from(MAX_CROSSINGS_PER_TX).unwrap() + 1;
        assert!(!star.decomposes(&legs, &[], &resolver()));
    }
}
