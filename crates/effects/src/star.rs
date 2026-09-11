//! The star classifier: how a routed transaction's participants divide
//! its execution.
//!
//! The classification is a pure function of the admitted manifest and a
//! shard placement, asked once where a transaction commits and frozen
//! from there. The placement-free half — each node's shape — is
//! [`legs_of`]. The placed half — the settled roles, the core, every
//! value edge that crosses, and whether the shape divides at all — is
//! [`star_at`], the one place any of those is decided.
//!
//! The vocabulary — [`LegRole`], [`ValueEdge`], [`LegShape`] — is
//! [`hyperscale_vm_types`]'s, so the protocol carries the classifier's
//! own reading rather than a copy of it.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_types::{Address, LegRole, LegShape, MAX_CROSSINGS_PER_TX, ValueEdge};

use crate::admission::{Admitted, NodeOrigin};
use crate::claim::Claim;
use crate::envelope::CrossingSite;
use crate::hash::Hasher;
use crate::manifest::{Manifest, NodeInput};
use crate::route::ShardResolver;
use crate::types::{EdgeContent, ShardId};

/// One value edge whose producer and consumer do not run together.
///
/// Generic over the shard identifier so an embedder can carry the star
/// under its own type without restating it: [`Star::map_shards`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossingEdge<S = ShardId> {
    /// The producing node.
    pub producer: u32,
    /// Which of its outputs the edge carries.
    pub output: u32,
    /// The consuming node.
    pub consumer: u32,
    /// The shard whose verdict commits the record cell: the producing
    /// node's home.
    pub from: S,
    /// The shards that claim it — every shard running the consumer that
    /// does not also run the producer. Several for a consumer inside a
    /// multi-shard core.
    pub to: BTreeSet<S>,
    /// Whether an outbound leg consumes it — a delivery's arrival, which
    /// the delivering member of each claiming shard waits on rather than
    /// the issuing one.
    pub delivers: bool,
    /// The record cell, under the producing node's target.
    pub record: CrossingSite,
    /// The claim cell the consumer writes when it takes the crossing,
    /// under the consuming node's target.
    pub claim: CrossingSite,
}

impl<S: Ord> CrossingEdge<S> {
    fn map_shards<T: Ord>(self, f: &impl Fn(S) -> T) -> CrossingEdge<T> {
        CrossingEdge {
            producer: self.producer,
            output: self.output,
            consumer: self.consumer,
            from: f(self.from),
            to: self.to.into_iter().map(f).collect(),
            delivers: self.delivers,
            record: self.record,
            claim: self.claim,
        }
    }
}

/// A classified transaction at one placement: the star its shape
/// implies, and whether it runs as one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Star<S = ShardId> {
    /// Where each manifest node sits in the star, in node order, once
    /// placement settled it.
    pub roles: Vec<LegRole>,
    /// Each node's home: the shard its target sits on, in node order.
    pub homes: Vec<S>,
    /// The shards the core's nodes sit on. Empty for a shape with no
    /// core, which [`Self::decomposes`] refuses.
    pub core: BTreeSet<S>,
    /// The value edges that cross, in `(producer, output)` order. Each
    /// is one certificate entry, which is what bounds them.
    pub edges: Vec<CrossingEdge<S>>,
    /// Whether running the legs where their state lives differs from
    /// running the whole of it on the core's shards, and every rule
    /// that makes dividing it correct holds.
    pub decomposes: bool,
}

impl<S: Ord + Copy> Star<S> {
    /// How many nodes the classified manifest has.
    ///
    /// # Panics
    ///
    /// Never: admission caps a manifest at
    /// [`MAX_MANIFEST_NODES`](hyperscale_vm_types::MAX_MANIFEST_NODES),
    /// far inside `u32`.
    #[must_use]
    pub fn nodes(&self) -> u32 {
        u32::try_from(self.homes.len()).expect("a manifest has fewer than u32 nodes")
    }

    /// The node's settled role. A node past the manifest is core, the
    /// direction every unsure answer takes.
    #[must_use]
    pub fn role(&self, node: u32) -> LegRole {
        role_at(&self.roles, node)
    }

    /// The shards that run `node`: every core shard for a core node, its
    /// home for a leg.
    ///
    /// The one reading of who runs what. An embedder dividing the same
    /// manifest reads it from here rather than from the fields, because
    /// two shards divide one manifest separately and a second copy of
    /// this answer is a crossing issued that nobody claims.
    #[must_use]
    pub fn running(&self, node: u32) -> BTreeSet<S> {
        running_at(&self.roles, &self.homes, &self.core, node)
    }

    /// Whether `shard` runs `node` as a delivery: it consumes a crossing
    /// that lands there, so the member running it waits on an arrival
    /// rather than producing what it consumes.
    ///
    /// Off the edges rather than off the role alone, and `delivers` is
    /// already the edge's word for "its consumer is an outbound leg", so
    /// this asks the one further question: does the value cross to
    /// `shard`. An outbound leg fed from beside itself crosses no
    /// boundary and answers `false`, which is right — its member issues.
    #[must_use]
    pub fn delivers_at(&self, node: u32, shard: S) -> bool {
        self.edges
            .iter()
            .any(|edge| edge.delivers && edge.consumer == node && edge.to.contains(&shard))
    }

    /// The whole shape on every participant: no placement read, nothing
    /// dividing.
    #[must_use]
    pub const fn whole() -> Self {
        Self {
            roles: Vec::new(),
            homes: Vec::new(),
            core: BTreeSet::new(),
            edges: Vec::new(),
            decomposes: false,
        }
    }

    /// The same star under another shard identifier.
    #[must_use]
    pub fn map_shards<T: Ord>(self, f: impl Fn(S) -> T) -> Star<T> {
        Star {
            roles: self.roles,
            homes: self.homes.into_iter().map(&f).collect(),
            core: self.core.into_iter().map(&f).collect(),
            edges: self
                .edges
                .into_iter()
                .map(|edge| edge.map_shards(&f))
                .collect(),
            decomposes: self.decomposes,
        }
    }
}

/// Each admitted node's placement-free shape, in node order.
///
/// Everything the envelope fixes about a node: its role, the edges it
/// consumes, the claims it presents, the owners it declares, and the
/// signed intent it came from. What placement adds is read off a
/// resolver at [`star_at`], and nothing here.
#[must_use]
pub fn legs_of(admitted: &Admitted) -> Vec<LegShape> {
    let manifest = admitted.manifest();
    let roles = classify_roles(
        manifest,
        admitted.origins(),
        &admitted.answered_at_admission(),
    );
    assemble(manifest, &roles, admitted.origins(), admitted.declares())
}

/// Classify every manifest node into the star, before placement.
///
/// The leg tests are structural, and each is read off the manifest's own
/// edges and the facts admission recorded of the method's signature
/// rather than off what a method is named:
///
/// - An **inbound** leg takes no value edge, so nothing the core produces
///   can be among its arguments, and its only movement is one reserve.
/// - An **attesting** leg takes no value edge and moves nothing at all.
/// - An **outbound** leg's output feeds nothing and nothing about it can
///   refuse: the verified total mark over its body, no evidence asked of
///   its caller, no declared bound on an edge it consumes, and a frame
///   admission alone answers.
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
/// or whose origin is missing is core on the same rule.
fn classify_roles(manifest: &Manifest, origins: &[NodeOrigin], answered: &[bool]) -> Vec<LegRole> {
    let consumed: BTreeSet<u32> = manifest
        .nodes
        .iter()
        .flat_map(|node| &node.inputs)
        .filter_map(|input| match input {
            NodeInput::Edge { source, .. } => Some(*source),
            NodeInput::Literal(_) => None,
        })
        .collect();

    (0u32..)
        .zip(&manifest.nodes)
        .map(|(index, node)| {
            let origin = origins
                .get(index as usize)
                .copied()
                .unwrap_or_else(|| NodeOrigin::unsigned(index));
            let takes_no_edge = node
                .inputs
                .iter()
                .all(|input| matches!(input, NodeInput::Literal(_)));
            let unrefusable = origin.unrefusable
                && answered.get(index as usize).copied().unwrap_or(false)
                && node.inputs.iter().all(|input| match input {
                    NodeInput::Edge { bounds, .. } => bounds.admit_anything(),
                    NodeInput::Literal(_) => true,
                });

            if takes_no_edge && origin.reservation_shaped {
                LegRole::Inbound
            } else if takes_no_edge && origin.commits_nothing {
                LegRole::Attesting
            } else if !consumed.contains(&index) && unrefusable {
                LegRole::Outbound
            } else {
                LegRole::Core
            }
        })
        .collect()
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
    (0u32..)
        .zip(&manifest.nodes)
        .map(|(index, node)| {
            let origin = origins
                .get(index as usize)
                .copied()
                .unwrap_or_else(|| NodeOrigin::unsigned(index));
            LegShape {
                target: node.target,
                role: roles.get(index as usize).copied().unwrap_or_default(),
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

/// Anchor a classification: settle every role against the placement,
/// read the core set off the settled roles, name every edge that
/// crosses, and decide whether the shape divides.
///
/// The half a parent re-derives at each anchor. Everything in `legs` is
/// fixed by the envelope, and this is the only part a reshape can move.
/// `owners` are the parties the transaction's routing declares beyond
/// any node's frame: the fee payer and every signer. `hasher` names the
/// cells each crossing writes.
#[must_use]
pub fn star_at(
    legs: &[LegShape],
    owners: &[Address],
    shards: &dyn ShardResolver,
    hasher: &dyn Hasher,
) -> Star {
    let homes: Vec<ShardId> = legs
        .iter()
        .map(|node| shards.shard_of(node.target))
        .collect();
    let roles = settle(legs, &homes);
    let core: BTreeSet<ShardId> = roles
        .iter()
        .zip(&homes)
        .filter(|(role, _)| **role == LegRole::Core)
        .map(|(_, home)| *home)
        .collect();
    let placed = Placed {
        legs,
        roles: &roles,
        homes: &homes,
        core: &core,
    };
    let edges = placed.crossing_edges(hasher);
    let decomposes = placed.decomposes(owners, &edges, shards);
    Star {
        roles,
        homes,
        core,
        edges,
        decomposes,
    }
}

/// Every role once placement has settled it.
///
/// Three rules, each about placement, which is why they run here and not
/// in [`classify_roles`].
///
/// **A proof must stay home.** A node presenting what an attesting node
/// proved runs in a world where that node succeeded, and under
/// decomposition it learns that by running beside it. A consumer on
/// another shard would have to take the proof as an attested value,
/// which is a second crossing kind and not one this design builds — so
/// the attesting node goes back to the core, where every participant
/// runs it. Which node proved a claim is not on the shape — the manifest
/// resolved the evidence into its subject — so the match is by subject.
/// A subject that is some node's own target names that node; a badge or
/// any other subject no node is names whichever attesting node proved
/// it, which is not known, so it is taken to name every one of them.
/// Over-flagging sends a proof to the core that could have stayed home,
/// which costs a replication; under-flagging would run a gate against a
/// proof its prover never made.
///
/// **The core must have a bearer.** A core with no node in it names no
/// shard for a refusal, a departure or an absence to be taken against,
/// so there is nothing for a reclaim to be admitted on. Where nothing
/// else is in the core, every write-free node is — all of them, so which
/// one bears the verdict is never a pick.
///
/// **A leg on a core shard is the core's.** Every leg whose home is a
/// core shard runs in the core member and is replicated where the core
/// is: an attesting node, an inbound leg whose crossing the core then
/// issues, an outbound leg whose crossing the core then claims. Nothing
/// is departed between a producer and a consumer that run together, and
/// no shard is both the core's and a leg's — a leg left beside the core
/// would settle its own crossing on a shard whose verdict the core
/// already gave, a member neither side of the star names.
fn settle(legs: &[LegShape], homes: &[ShardId]) -> Vec<LegRole> {
    let mut settled: Vec<LegRole> = legs.iter().map(|node| node.role).collect();
    for (index, node) in legs.iter().enumerate() {
        if settled.get(index) != Some(&LegRole::Attesting) {
            continue;
        }
        let here = homes[index];
        let names_me = |subject: &Address| {
            *subject == node.target || !legs.iter().any(|other| other.target == *subject)
        };
        let stays_home = legs
            .iter()
            .zip(homes)
            .all(|(other, home)| *home == here || !other.presents.iter().any(names_me));
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

    // The core set is read once: folding a leg whose home is already in
    // it adds no shard, so one pass settles every role.
    let core: BTreeSet<ShardId> = settled
        .iter()
        .zip(homes)
        .filter(|(role, _)| **role == LegRole::Core)
        .map(|(_, home)| *home)
        .collect();
    for (role, home) in settled.iter_mut().zip(homes) {
        if core.contains(home) {
            *role = LegRole::Core;
        }
    }
    settled
}

/// The node's settled role. A node past the manifest is core, the
/// direction every unsure answer takes.
fn role_at(roles: &[LegRole], node: u32) -> LegRole {
    roles.get(node as usize).copied().unwrap_or_default()
}

/// The shards that run `node`: every core shard for a core node, its
/// home for a leg.
fn running_at<S: Ord + Copy>(
    roles: &[LegRole],
    homes: &[S],
    core: &BTreeSet<S>,
    node: u32,
) -> BTreeSet<S> {
    match role_at(roles, node) {
        LegRole::Core => core.clone(),
        LegRole::Inbound | LegRole::Outbound | LegRole::Attesting => {
            homes.get(node as usize).copied().into_iter().collect()
        }
    }
}

/// The shape at its placement: what every question below reads.
///
/// Half a [`Star`] — everything but the edges and the verdict, which is
/// what the questions here are asked in order to produce — plus the legs
/// they are asked against. So the two derivations both sides need read
/// through [`role_at`] and [`running_at`] rather than either owning them.
struct Placed<'a> {
    legs: &'a [LegShape],
    roles: &'a [LegRole],
    homes: &'a [ShardId],
    core: &'a BTreeSet<ShardId>,
}

impl Placed<'_> {
    fn role(&self, node: u32) -> LegRole {
        role_at(self.roles, node)
    }

    fn running(&self, node: u32) -> BTreeSet<ShardId> {
        running_at(self.roles, self.homes, self.core, node)
    }

    /// Every value edge whose producer and consumer do not run together,
    /// in `(producer, output)` order.
    ///
    /// Read off which shards run each node rather than off homes alone:
    /// an edge between two core nodes on two shards crosses nothing,
    /// since every core shard runs both, and a leg folded into the core
    /// hands its value to the core member it runs in.
    fn crossing_edges(&self, hasher: &dyn Hasher) -> Vec<CrossingEdge> {
        let mut edges = Vec::new();
        for (consumer, node) in (0u32..).zip(self.legs) {
            for edge in &node.edges {
                let Some(producer) = self.legs.get(edge.source as usize) else {
                    continue;
                };
                let to: BTreeSet<ShardId> = self
                    .running(consumer)
                    .difference(&self.running(edge.source))
                    .copied()
                    .collect();
                if to.is_empty() {
                    continue;
                }
                edges.push(CrossingEdge {
                    producer: edge.source,
                    output: edge.output,
                    consumer,
                    from: self.homes[edge.source as usize],
                    to,
                    delivers: self.role(consumer) == LegRole::Outbound,
                    record: CrossingSite::record_of(hasher, producer, edge.output),
                    claim: CrossingSite::claim_of(hasher, node.target, producer, edge.output),
                });
            }
        }
        edges.sort_by_key(|edge| (edge.producer, edge.output));
        edges
    }

    /// Whether running this transaction's legs where their state lives
    /// differs from running the whole of it on the core's shards, and
    /// every rule that makes dividing it correct holds.
    ///
    /// Every conjunct refuses rather than admits — running whole is
    /// always correct, so an unsure answer takes it.
    fn decomposes(
        &self,
        owners: &[Address],
        edges: &[CrossingEdge],
        shards: &dyn ShardResolver,
    ) -> bool {
        let participants: BTreeSet<ShardId> = self.homes.iter().copied().collect();
        self.core_bears_a_verdict()
            && self.a_leg_sits_off_the_core()
            && Self::crossings_fit(edges)
            && Self::every_route_owner_participates(&participants, owners, shards)
            && self.every_node_declares_inside_its_scope(shards)
            && self.every_edge_has_one_consumer()
            && self.no_named_instance_touches_a_leg()
            && self.no_sink_is_fed_from_both_sides()
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
    fn a_leg_sits_off_the_core(&self) -> bool {
        self.roles
            .iter()
            .zip(self.homes)
            .any(|(role, home)| *role != LegRole::Core && !self.core.contains(home))
    }

    /// Each crossing is a fixed-width entry in the receipt leaf, so a
    /// shape carrying more than one outcome can encode is one no
    /// participant could state a verdict for.
    const fn crossings_fit(edges: &[CrossingEdge]) -> bool {
        edges.len() <= MAX_CROSSINGS_PER_TX
    }

    /// Every party the routing declares beyond any node's frame — the
    /// fee payer, whose vault the reservation and the burn reach, and
    /// every signer, whose nullifier a bound subintent writes — sits on
    /// a shard that runs a member, so some member's scope covers it.
    ///
    /// What is excluded is a shard that runs nothing. A payer on such a
    /// shard is a routing participant with no member: the shard would
    /// freeze divided, compose a member and find no plan for it, and
    /// attest a refusal with the price apart while the core committed. A
    /// signer likewise would have their nullifier written by whichever
    /// member happened to run there, after the core committed or never.
    /// Running whole provisions the vault and writes the nullifier where
    /// a whole execution always did.
    ///
    /// The test is per shard and not per node, which is what it means to
    /// say some member's scope covers the owner: a payer whose shard
    /// runs only a delivery passes, and should. What provisions the
    /// vault and takes the reservation is that the shard runs a member
    /// at all, not which role that member plays.
    fn every_route_owner_participates(
        participants: &BTreeSet<ShardId>,
        owners: &[Address],
        shards: &dyn ShardResolver,
    ) -> bool {
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
    ///
    /// The case that makes this real is a reaching access rather than a
    /// deposit: a reach puts the read under the reached party's owner,
    /// who need not be any node's target — where a movement's owner is
    /// the moving party and usually is one, so a reader checking only
    /// deposits concludes this cannot happen.
    fn every_node_declares_inside_its_scope(&self, shards: &dyn ShardResolver) -> bool {
        self.roles
            .iter()
            .zip(self.legs)
            .zip(self.homes)
            .all(|((role, node), home)| {
                node.declares.iter().all(|owner| {
                    let at = shards.shard_of(*owner);
                    match role {
                        LegRole::Core => self.core.contains(&at),
                        LegRole::Inbound | LegRole::Outbound | LegRole::Attesting => at == *home,
                    }
                })
            })
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
    fn every_edge_has_one_consumer(&self) -> bool {
        let mut consumers: BTreeMap<(u32, u32), u32> = BTreeMap::new();
        for node in self.legs {
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
    fn no_named_instance_touches_a_leg(&self) -> bool {
        let is_leg = |node: u32| self.role(node) != LegRole::Core;
        (0u32..).zip(self.legs).all(|(index, node)| {
            node.edges
                .iter()
                .all(|edge| !edge.non_fungible || !(is_leg(index) || is_leg(edge.source)))
        })
    }

    /// Whether every sink's producers all run where it does, or none do.
    ///
    /// A sink fed from both sides has no member that can run it: its
    /// shard's issuing member would have to hand it the local edge
    /// through a bundle to itself, and its delivering member waits on an
    /// arrival that edge never produces. Read off the settled roles, so
    /// a leg folded into the core is asked about where the core runs
    /// rather than where its own prefix sits.
    fn no_sink_is_fed_from_both_sides(&self) -> bool {
        (0u32..).zip(self.legs).all(|(node, leg)| {
            if self.role(node) != LegRole::Outbound {
                return true;
            }
            let home = self.homes[node as usize];
            let beside: BTreeSet<bool> = leg
                .edges
                .iter()
                .map(|edge| self.running(edge.source).contains(&home))
                .collect();
            beside.len() <= 1
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_vm_types::{
        AddressClass, CallTarget, MAX_CROSSINGS_PER_TX, Moves, ResourceAddr, SubintentHash,
        ValueEdge,
    };

    use super::{Address, LegRole, LegShape, NodeOrigin, Star, assemble, classify_roles, star_at};
    use crate::claim::Claim;
    use crate::dsl::{Clause, Expr, ModeExpr};
    use crate::hash::{Hash32, TestHasher};
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

    /// Each node's origin as admission records it: unsigned, and carrying
    /// what the signature its call resolves to on `chain` says of it.
    fn origins_of(manifest: &Manifest, chain: &Records) -> Vec<NodeOrigin> {
        (0u32..)
            .zip(&manifest.nodes)
            .map(|(index, node)| {
                let signature = CallTarget::try_from(node.target)
                    .ok()
                    .and_then(|target| chain.instance(target))
                    .and_then(|meta| chain.package(meta.package))
                    .and_then(|package| package.methods.get(&node.method).cloned())
                    .expect("the fixture resolves every target");
                let unsigned = NodeOrigin::unsigned(index);
                NodeOrigin::of(unsigned.intent, index, unsigned.expiry_ms, &signature)
            })
            .collect()
    }

    /// The legs a hand-built manifest implies under `answered`, each
    /// declaring exactly its own target — the ordinary case, so a test
    /// about anything else states its own declaration instead.
    fn legs_under(manifest: &Manifest, chain: &Records, answered: &[bool]) -> Vec<LegShape> {
        let origins = origins_of(manifest, chain);
        let roles = classify_roles(manifest, &origins, answered);
        assemble(manifest, &roles, &origins, Vec::new())
    }

    /// The legs a hand-built manifest implies, every frame answered by
    /// admission alone.
    fn legs(manifest: &Manifest, chain: &Records) -> Vec<LegShape> {
        legs_under(manifest, chain, &answered(manifest))
    }

    /// The star `legs` imply under the test placement, over a routing
    /// declaring nobody beyond the nodes.
    fn placed(legs: &[LegShape]) -> Star {
        star_at(legs, &[], &resolver(), &TestHasher)
    }

    /// The star and the legs it was read off, since several tests want
    /// to move the legs and read the star again.
    fn star_and_shape(manifest: &Manifest, chain: &Records) -> (Star, Vec<LegShape>) {
        let legs = legs(manifest, chain);
        (placed(&legs), legs)
    }

    /// Whether the shape decomposes, over a declaration reaching exactly
    /// its own nodes and a routing declaring nobody beyond them.
    fn decomposes(manifest: &Manifest, chain: &Records) -> bool {
        star_and_shape(manifest, chain).0.decomposes
    }

    /// A hand-built leg at `target` consuming `edges` as `(source,
    /// output)`, declaring exactly its own target.
    fn leg(target: Address, role: LegRole, edges: &[(u32, u32)], local: u32) -> LegShape {
        LegShape {
            target,
            role,
            edges: edges
                .iter()
                .map(|&(source, output)| ValueEdge {
                    source,
                    output,
                    non_fungible: false,
                })
                .collect(),
            presents: Vec::new(),
            declares: vec![target],
            intent: SubintentHash(Hash32([7; 32])),
            local,
            expiry_ms: 1_000,
        }
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

    /// The readings an embedder divides a manifest by, which is the
    /// reason they are on [`Star`] rather than derived beside it: a
    /// second copy of "who runs this node" is a crossing issued that
    /// nobody claims.
    #[test]
    fn the_star_answers_who_runs_each_node() {
        let (chain, manifest) = star_world(Totality::Total);
        let star = placed(&legs(&manifest, &chain));
        assert!(
            star.decomposes,
            "the fixture divides, or this proves little"
        );

        assert_eq!(star.nodes(), 3);
        assert_eq!(star.role(0), LegRole::Inbound);
        assert_eq!(star.role(1), LegRole::Core);
        assert_eq!(star.role(2), LegRole::Outbound);
        assert_eq!(
            star.role(3),
            LegRole::Core,
            "a node past the manifest takes the direction every unsure answer takes",
        );

        assert_eq!(
            star.running(1),
            star.core,
            "a core node runs on every core shard"
        );
        assert_eq!(
            star.running(0),
            BTreeSet::from([star.homes[0]]),
            "a leg runs on its own home",
        );

        assert!(
            star.delivers_at(2, star.homes[2]),
            "the sink consumes what crossed to it",
        );
        assert!(
            !star.delivers_at(2, star.homes[1]),
            "and issues nowhere the value did not cross to",
        );
        assert!(
            !star.delivers_at(0, star.homes[0]),
            "a source delivers nothing: it consumes no edge at all",
        );
    }

    /// A call that stays on one shard crosses nothing, so a staged
    /// execution of it would pay for no boundary at all.
    #[test]
    fn a_single_shard_transaction_alternates_zero_times() {
        let (chain, manifest) = solo_world();
        let star = placed(&legs(&manifest, &chain));
        assert!(star.edges.is_empty());
    }

    /// A call reaching a core node on another shard crosses nothing: the
    /// core spans both shards, every core shard runs both ends, and the
    /// edge stays inside the execution each of them replicates.
    #[test]
    fn a_call_between_two_core_shards_crosses_nothing() {
        let (chain, manifest) = payer_payee_world();
        assert_ne!(
            resolver().shard_of(instance_of("payer").into()),
            resolver().shard_of(instance_of("payee").into()),
            "the fixture has to straddle, or the verdict below proves nothing",
        );
        let star = placed(&legs(&manifest, &chain));
        assert!(
            star.roles.iter().all(|role| *role == LegRole::Core),
            "both ends are core: {:?}",
            star.roles,
        );
        assert_eq!(star.core.len(), 2);
        assert!(star.edges.is_empty());
    }

    /// A value edge is a dependency like a call is: the consumer cannot
    /// run until the producer's output exists, so a total consumer on
    /// another shard is a boundary even though neither node calls the
    /// other. The edge names both cells: the record under the producer,
    /// the claim under the consumer.
    #[test]
    fn a_value_edge_to_a_leg_on_another_shard_crosses_once() {
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
            MethodSignature {
                totality: Totality::Total,
                effects: vec![self_point(
                    SlotId(2),
                    ModeExpr::Delta { moves: Moves::Both },
                )],
                ..MethodSignature::default()
            },
        );
        chain.packages.publish_unchecked(pkg("producer"), producing);
        chain.packages.publish_unchecked(pkg("consumer"), consuming);
        chain.instances.create(&TestHasher, meta_of("producer"));
        chain.instances.create(&TestHasher, meta_of("consumer"));
        let (producer, consumer): (Address, Address) = (
            instance_of("producer").into(),
            instance_of("consumer").into(),
        );
        assert_ne!(
            resolver().shard_of(producer),
            resolver().shard_of(consumer),
            "the fixture has to straddle, or the depth below proves nothing",
        );

        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: producer,
                    method: "make".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                },
                Node {
                    target: consumer,
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

        let star = placed(&legs(&manifest, &chain));
        assert_eq!(star.roles, vec![LegRole::Core, LegRole::Outbound]);
        assert_eq!(star.edges.len(), 1);
        let edge = &star.edges[0];
        assert_eq!((edge.producer, edge.output, edge.consumer), (0, 0, 1));
        assert!(edge.delivers, "an outbound leg takes it as a delivery");
        assert_eq!(edge.from, resolver().shard_of(producer));
        assert_eq!(edge.to, BTreeSet::from([resolver().shard_of(consumer)]));
        assert_eq!(edge.record.key().owner, producer);
        assert_eq!(edge.claim.key().owner, consumer);
    }

    /// The reservation-shaped source is the inbound leg: nothing the core
    /// produces reaches its arguments, so it can run first, and the
    /// reserve is what lets its refusal release rather than abort.
    #[test]
    fn a_reservation_shaped_source_is_an_inbound_leg() {
        let (chain, manifest) = star_world(Totality::Fallible);
        let star = placed(&legs(&manifest, &chain));
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
            let star = placed(&legs(&manifest, &chain));
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

        let star = placed(&legs(&manifest, &chain));
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

        let star = placed(&legs(&manifest, &chain));
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
            placed(&legs(&manifest, &chain)).roles[2],
            LegRole::Outbound,
            "the fixture has to be outbound unbounded, or the verdict below proves nothing",
        );
        assert_eq!(placed(&legs(&bounded, &chain)).roles[2], LegRole::Core);
    }

    /// A frame carrying a verdict later than admission is one an outbound
    /// leg may not have: it materializes on its own shard after the core
    /// committed, so the refusal lands on a caller that already did.
    #[test]
    fn a_sink_judged_later_than_admission_is_core() {
        let (chain, manifest) = star_world(Totality::Total);
        let mut later = answered(&manifest);
        later[2] = false;

        assert_eq!(placed(&legs(&manifest, &chain)).roles[2], LegRole::Outbound);
        assert_eq!(
            placed(&legs_under(&manifest, &chain, &later)).roles[2],
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

        let star = placed(&legs(&manifest, &chain));
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
            let star = placed(&legs(&manifest, &chain));
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

        let star = placed(&legs(&manifest, &chain));
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
        let roles = classify_roles(
            &manifest,
            &origins_of(&manifest, &chain),
            &answered(&manifest),
        );
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
        assert!(star.decomposes, "the sink is off the core");
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
        assert!(star.decomposes);
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

    /// A leg whose home is a core shard is the core member's: the venue's
    /// output to a recipient on the venue's own shard is passed directly
    /// rather than departed into a record the shard could never be
    /// handed, and an inbound leg beside the core is replicated with it.
    #[test]
    fn a_leg_beside_the_core_is_the_cores() {
        let here = Address::new([0x11; 31], AddressClass::Component);
        let venue = Address::new([0x91; 31], AddressClass::Component);
        let mut beside = [0x22; 31];
        beside[0] = 0x91;
        let recipient = Address::new(beside, AddressClass::Component);
        assert_ne!(resolver().shard_of(here), resolver().shard_of(venue));
        assert_eq!(resolver().shard_of(venue), resolver().shard_of(recipient));
        let legs = vec![
            leg(here, LegRole::Attesting, &[], 0),
            leg(here, LegRole::Inbound, &[], 1),
            leg(venue, LegRole::Core, &[(1, 0)], 2),
            leg(recipient, LegRole::Outbound, &[(2, 0)], 3),
        ];
        let star = placed(&legs);
        assert_eq!(
            star.roles,
            vec![
                LegRole::Attesting,
                LegRole::Inbound,
                LegRole::Core,
                LegRole::Core
            ],
            "the deposit beside the venue is the core's; the caller's legs stay legs",
        );
        assert_eq!(
            star.edges
                .iter()
                .map(|edge| edge.producer)
                .collect::<Vec<_>>(),
            vec![1],
            "only the withdraw crosses",
        );
        assert!(star.decomposes);
    }

    /// Every leg on a core shard folds, whatever it feeds: a top-up
    /// beside the first venue feeding the route's sink is the core's
    /// along with the sink. Left a leg, the edge between them would be a
    /// crossing on a multi-shard core — one the shard running both ends
    /// never departs, and one the core's other shards wait on for good.
    #[test]
    fn a_leg_whose_consumer_folds_beside_the_core_folds_with_it() {
        let caller = Address::new([0x11; 31], AddressClass::Component);
        let venue_a = Address::new([0x91; 31], AddressClass::Component);
        let venue_b = Address::new([0x33; 31], AddressClass::Component);
        let beside = |tail: u8| {
            let mut bytes = [tail; 31];
            bytes[0] = 0x91;
            Address::new(bytes, AddressClass::Component)
        };
        let (topup, sink) = (beside(0x55), beside(0x77));
        assert_eq!(resolver().shard_of(venue_a), resolver().shard_of(topup));
        assert_eq!(resolver().shard_of(venue_a), resolver().shard_of(sink));
        assert_ne!(resolver().shard_of(venue_a), resolver().shard_of(venue_b));
        assert_ne!(resolver().shard_of(venue_a), resolver().shard_of(caller));

        // A route across two venues, with a top-up beside the first one
        // feeding the same sink the route ends in.
        let legs = vec![
            leg(caller, LegRole::Inbound, &[], 0),
            leg(venue_a, LegRole::Core, &[(0, 0)], 1),
            leg(venue_b, LegRole::Core, &[(1, 0)], 2),
            leg(topup, LegRole::Inbound, &[], 3),
            leg(sink, LegRole::Outbound, &[(2, 0), (3, 0)], 4),
        ];
        let star = placed(&legs);
        assert_eq!(
            star.roles,
            vec![
                LegRole::Inbound,
                LegRole::Core,
                LegRole::Core,
                LegRole::Core,
                LegRole::Core,
            ],
            "the sink folds beside the core, and the top-up feeding it folds with it",
        );
        assert!(star.decomposes);
        assert_eq!(
            star.edges
                .iter()
                .map(|edge| edge.producer)
                .collect::<Vec<_>>(),
            vec![0],
            "only the caller's leg crosses: nothing departs between two nodes the core runs",
        );
    }

    /// An outbound leg on a core shard is the core's even when what
    /// feeds it is a leg elsewhere: the crossing is then one the core
    /// claims rather than a delivery, so the shard is never both the
    /// core's and a delivery's.
    #[test]
    fn a_sink_beside_the_core_fed_from_off_it_is_the_cores() {
        let venue = Address::new([0x91; 31], AddressClass::Component);
        let caller = Address::new([0x11; 31], AddressClass::Component);
        let mut beside = [0x22; 31];
        beside[0] = 0x91;
        let recipient = Address::new(beside, AddressClass::Component);
        assert_ne!(resolver().shard_of(caller), resolver().shard_of(venue));
        assert_eq!(resolver().shard_of(venue), resolver().shard_of(recipient));
        let legs = vec![
            leg(venue, LegRole::Core, &[], 0),
            leg(caller, LegRole::Inbound, &[], 1),
            leg(recipient, LegRole::Outbound, &[(1, 0)], 2),
        ];
        let star = placed(&legs);
        assert_eq!(
            star.roles,
            vec![LegRole::Core, LegRole::Inbound, LegRole::Core],
            "the sink beside the venue is the core's; the caller's leg stays a leg",
        );
        assert_eq!(star.edges.len(), 1, "the caller's leg crosses once");
        assert!(
            !star.edges[0].delivers,
            "and the core claims it rather than a delivery"
        );
        assert!(star.decomposes);
    }

    /// A declaration reaching a party that runs nothing would leave that
    /// target judged by nobody, where a whole execution judged it
    /// everywhere.
    #[test]
    fn a_declaration_reaching_a_non_participant_does_not_decompose() {
        let (chain, manifest) = star_world(Totality::Total);
        let (star, mut legs) = star_and_shape(&manifest, &chain);
        assert!(star.decomposes);

        legs[0].declares.push(instance_of("stranger").into());
        assert!(!placed(&legs).decomposes);
    }

    /// A party the routing declares beyond any node — a sponsored payer,
    /// a signer with no node of their own — has to sit on a shard some
    /// member runs on, or the shape runs whole: divided, that shard would
    /// compose a member with nothing to run and refuse while the core
    /// committed.
    #[test]
    fn a_route_owner_off_every_participant_does_not_decompose() {
        let (chain, manifest) = star_world(Totality::Total);
        let legs = legs(&manifest, &chain);
        let participant = legs[0].target;
        let over = |owners: &[Address]| star_at(&legs, owners, &resolver(), &TestHasher).decomposes;
        assert!(over(&[participant]));

        let stranger: Address = instance_of("stranger").into();
        assert!(!over(&[stranger]));
        assert!(!over(&[participant, stranger]));
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
        assert!(star.decomposes);

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
        assert!(!placed(&legs).decomposes);
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

    /// A sink fed from both sides of its own shard runs whole: its
    /// issuing member could only hand it the local edge through a bundle
    /// to itself, and its delivering member waits on an arrival that
    /// edge never produces.
    #[test]
    fn a_sink_fed_from_both_sides_does_not_decompose() {
        let alice = Address::new([0x11; 31], AddressClass::Component);
        let venue = Address::new([0x91; 31], AddressClass::Component);
        assert_ne!(resolver().shard_of(alice), resolver().shard_of(venue));
        let mut legs = vec![
            leg(alice, LegRole::Attesting, &[], 0),
            leg(alice, LegRole::Inbound, &[], 1),
            leg(venue, LegRole::Core, &[(1, 0)], 2),
            leg(alice, LegRole::Inbound, &[], 3),
            leg(alice, LegRole::Outbound, &[(2, 0), (3, 0)], 4),
        ];
        assert!(!placed(&legs).decomposes);

        legs[4] = leg(alice, LegRole::Outbound, &[(2, 0)], 4);
        legs[3] = leg(alice, LegRole::Outbound, &[], 3);
        assert!(
            placed(&legs).decomposes,
            "fed from one side, the sink is a delivery"
        );
    }

    /// Past the cap a shape carries more crossings than one outcome can
    /// state a verdict for, so no participant could encode one.
    #[test]
    fn a_shape_past_the_crossing_cap_does_not_decompose() {
        let here = Address::new([0x11; 31], AddressClass::Component);
        let there = Address::new([0x91; 31], AddressClass::Component);
        assert_ne!(resolver().shard_of(here), resolver().shard_of(there));
        // A sign-in with nothing else in the core bears the verdict; each
        // withdraw beside it crosses to a deposit elsewhere.
        let fan_out = |crossings: usize| -> Vec<LegShape> {
            let mut legs = vec![leg(here, LegRole::Attesting, &[], 0)];
            for _ in 0..crossings {
                let withdraw = u32::try_from(legs.len()).expect("a small manifest");
                legs.push(leg(here, LegRole::Inbound, &[], withdraw));
                legs.push(leg(
                    there,
                    LegRole::Outbound,
                    &[(withdraw, 0)],
                    withdraw + 1,
                ));
            }
            legs
        };

        let fits = placed(&fan_out(MAX_CROSSINGS_PER_TX));
        assert_eq!(fits.edges.len(), MAX_CROSSINGS_PER_TX);
        assert!(fits.decomposes);

        let past = placed(&fan_out(MAX_CROSSINGS_PER_TX + 1));
        assert_eq!(past.edges.len(), MAX_CROSSINGS_PER_TX + 1);
        assert!(!past.decomposes);
    }
}
