//! The star classifier: how a routed transaction's participants could
//! divide its execution.
//!
//! Standalone from the routing fold — nothing on the execution path
//! consumes the verdict yet, and the classification is a pure function
//! of the manifest, the metadata, and shard placement, so it is asked
//! where it is wanted rather than computed on every `route()` call.

use std::collections::BTreeSet;

use hyperscale_vm_types::CallTarget;

use crate::dsl::{Clause, ModeExpr};
use crate::instance::InstanceRegistry;
use crate::manifest::{Manifest, NodeInput};
use crate::metadata::MetadataCache;
use crate::route::ShardResolver;
use crate::signature::{MethodSignature, Totality};
use crate::types::EdgeContent;

/// The deepest route staging is admissible for.
///
/// A budget rather than a capability. Staging never wins on latency —
/// every stage past the first adds an inclusion-to-certification gap and
/// a composition wait, where replication fetches every counterpart's
/// committed reads in one round whatever the shape — so what it buys is
/// the deleted replicated executions and the hot shard's decongestion,
/// and what it costs is settlement latency. Measured against a gap of one
/// block, a staged route runs about 1.6 times the replicated equivalent's
/// settlement at depth two and about 2.1 at depth three; the budget is
/// twice, so two is admitted and three is refused.
pub const MAX_STAGED_DEPTH: u32 = 2;

/// How a transaction's participants divide its execution.
///
/// Both are always correct and the choice is a cost decision, which is
/// why it can be derived rather than declared: replication is never
/// unavailable, and it is the fallback for every shape where staging
/// costs more than it saves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strategy {
    /// Every participant executes the whole manifest and computes the
    /// same result from the same committed inputs.
    #[default]
    Replicated,
    /// Each participant executes only the legs whose cells it owns and
    /// takes every other leg's result as an attested value.
    LegLocal,
}

/// Where a manifest node sits in the star a decomposable transaction
/// takes the shape of.
///
/// The topology is one core with legs on either side of it, and the two
/// leg kinds differ by which side: an inbound leg runs before the core and
/// hands it attested value, an outbound leg runs after and cannot refuse
/// what it is handed. Everything else is core, which is what the
/// transaction's atomicity has to cover.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Runs before the core, on arguments the core did not produce, and
    /// commits locally: its refusal is the escrow release path rather
    /// than the core's problem.
    Inbound,
    /// Neither leg. The default in both senses — what a node is when
    /// nothing lets it decompose, and what the star is organised around.
    #[default]
    Core,
    /// Runs after the core and offers it no veto: nothing it does can
    /// come back as a refusal the core would have to answer.
    Outbound,
}

/// A classified transaction: the star its shape implies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StarShape {
    /// Where each manifest node sits in the star, in node order.
    pub roles: Vec<Role>,
    /// How many times the longest dependency chain changes shard. Zero
    /// exactly when the whole structure sits on one shard, which is what
    /// says there is nothing to decompose.
    pub crossings: u32,
    /// How many of those crossings something waits on — the settlement
    /// latency staging would add, and what [`MAX_STAGED_DEPTH`] budgets.
    /// Lower than [`Self::crossings`] by the crossings into outbound
    /// legs, which the core commits without hearing back from.
    pub stages: u32,
    /// How this transaction's participants divide its execution.
    pub strategy: Strategy,
}

/// Classify a manifest into the star its shape implies.
#[must_use]
pub fn classify(
    manifest: &Manifest,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    shards: &dyn ShardResolver,
) -> StarShape {
    let roles = classify_roles(manifest, cache, instances);
    let (crossings, stages) = chain_depths(manifest, shards, &roles);
    let strategy = classify_strategy(manifest, &roles, crossings, stages);
    StarShape {
        roles,
        crossings,
        stages,
        strategy,
    }
}

/// Classify every manifest node into the star.
///
/// The two leg tests are structural, and both are read off the manifest's
/// own edges rather than off what a method is named:
///
/// - An **inbound** leg takes no value edge, so nothing the core produces
///   can be among its arguments — L3's core-independence, falling out of
///   the shape instead of needing its own analysis — and it is
///   reservation-shaped: one reserve declared, one value out.
/// - An **outbound** leg's output feeds nothing, and its method carries
///   the verified [`Totality::Total`] mark, so the core cannot be made to
///   wait on a verdict it might refuse.
///
/// Every other node is core, and so is every node either test is unsure
/// about. That direction is the safe one: a node wrongly called core
/// costs the transaction a decomposition it could have had, while a leg
/// wrongly peeled off the core costs the atomicity the core exists for.
fn classify_roles(
    manifest: &Manifest,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
) -> Vec<Role> {
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
            let signature = CallTarget::try_from(node.target)
                .ok()
                .and_then(|target| instances.get(target))
                .and_then(|meta| cache.get(meta.package))
                .and_then(|pkg| pkg.methods.get(&node.method));
            let Some(signature) = signature else {
                return Role::Core;
            };
            let takes_no_edge = node
                .inputs
                .iter()
                .all(|input| matches!(input, NodeInput::Literal(_)));
            let index = u32::try_from(index).unwrap_or(u32::MAX);

            if takes_no_edge && is_reservation_shaped(signature) {
                Role::Inbound
            } else if !consumed.contains(&index) && signature.totality == Totality::Total {
                Role::Outbound
            } else {
                Role::Core
            }
        })
        .collect()
}

/// Whether a signature is the shape an inbound leg has to be: it declares
/// a conditional decrement, and it yields exactly one value out.
///
/// The reserve is what makes the leg's refusal local — the amount is
/// judged where the funds live, and a refusal there releases rather than
/// aborting the core — and the single output is what makes the value it
/// yields nameable as one escrow certificate.
fn is_reservation_shaped(signature: &MethodSignature) -> bool {
    signature.outputs.len() == 1
        && signature
            .effects
            .iter()
            .flat_map(Clause::effects)
            .any(|clause| {
                matches!(
                    clause,
                    Clause::Effect {
                        mode: ModeExpr::Reserve(_),
                        ..
                    }
                )
            })
}

/// Decide how this transaction's participants divide its execution.
///
/// Three things refuse staging, and each for its own reason:
///
/// - **Nothing crosses.** A transaction whose dependency structure sits
///   on one shard has one participant, so the two strategies name the
///   same execution and the honest verdict is the one that claims less.
/// - **It crosses too often.** Past [`MAX_STAGED_DEPTH`] the settlement
///   latency staging adds outruns the replicated work it deletes.
/// - **A leg moves a named instance.** The supply-delta attestation an
///   escrow certificate carries is linear over amounts and blind to
///   identity, so a fabricated non-fungible credit would arrive with a
///   delta its producer's history supports. Fungible legs are bounded by
///   that attestation; non-fungible ones are not, so they wait for one
///   that knows about ids. The test is over legs alone: a core's
///   participants reach agreement by unanimity rather than by attested
///   value, so nothing inside one is exposed to it.
fn classify_strategy(manifest: &Manifest, roles: &[Role], crossings: u32, stages: u32) -> Strategy {
    if crossings == 0 || stages > MAX_STAGED_DEPTH {
        return Strategy::Replicated;
    }
    let is_leg = |index: usize| matches!(roles.get(index), Some(Role::Inbound | Role::Outbound));
    for (index, node) in manifest.nodes.iter().enumerate() {
        for input in &node.inputs {
            let NodeInput::Edge {
                source, content, ..
            } = input
            else {
                continue;
            };
            if matches!(content, EdgeContent::NonFungible { .. })
                && (is_leg(index) || is_leg(*source as usize))
            {
                return Strategy::Replicated;
            }
        }
    }
    Strategy::LegLocal
}

/// How far the longest dependency chain reaches, counted two ways.
///
/// Returns `(crossings, stages)`. Both walk the same graph and differ
/// only in what a step costs, because the two questions they answer are
/// different: whether a transaction reaches beyond one shard at all, and
/// how much settlement latency staging it would add.
///
/// **Crossings** counts every shard change along the chain. It is the
/// structural fact — a chain returning to a shard it already visited has
/// crossed twice — and what says whether there is anything to decompose.
///
/// **Stages** counts only the crossings something waits on. A crossing
/// into an outbound leg costs nothing: the leg cannot refuse, so the core
/// commits without hearing back and no latency accrues on the far side of
/// it. This is the quantity [`MAX_STAGED_DEPTH`] budgets, and the two
/// diverge by exactly the outbound crossings — a single-venue swap
/// crosses twice to reach the venue and return, and stages once.
///
/// One forward pass in node-index order: a value edge runs from a lower
/// node index to a higher one — admission refuses anything else — so by
/// the time a consumer is visited every producer's depth is final. An
/// edge that violates the order could only appear in a hand-built
/// manifest, and it contributes nothing rather than being searched.
fn chain_depths(manifest: &Manifest, shards: &dyn ShardResolver, roles: &[Role]) -> (u32, u32) {
    // A crossing whose destination is an outbound leg costs no stage:
    // the leg cannot refuse, so nothing on the far side of it is waited
    // on and the chain ends there as far as latency is concerned. Every
    // other crossing is a stage, including one into a call the roles do
    // not describe, which is the conservative reading.
    let waited_on = |node: usize| -> bool { !matches!(roles.get(node), Some(Role::Outbound)) };

    let mut crossings = vec![0u32; manifest.nodes.len()];
    let mut stages = vec![0u32; manifest.nodes.len()];
    for (index, node) in manifest.nodes.iter().enumerate() {
        let to = shards.shard_of(node.target);
        for input in &node.inputs {
            let NodeInput::Edge { source, .. } = *input else {
                continue;
            };
            let source = source as usize;
            if source >= index {
                continue;
            }
            let crossed = shards.shard_of(manifest.nodes[source].target) != to;
            let crossed_here = crossings[source].saturating_add(u32::from(crossed));
            crossings[index] = crossings[index].max(crossed_here);
            let staged_here = stages[source].saturating_add(u32::from(crossed && waited_on(index)));
            stages[index] = stages[index].max(staged_here);
        }
    }
    (
        crossings.iter().copied().max().unwrap_or(0),
        stages.iter().copied().max().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::{MAX_STAGED_DEPTH, Role, Strategy, classify, classify_strategy};
    use crate::dsl::{Expr, ModeExpr};
    use crate::hash::TestHasher;
    use crate::instance::InstanceRegistry;
    use crate::manifest::{Bounds, Manifest, Node, NodeInput};
    use crate::metadata::{MetadataCache, PackageMetadata};
    use crate::route::ShardResolver;
    use crate::signature::{MethodSignature, Totality};
    use crate::test_worlds::{
        instance_of, issued_by, meta_of, method, payer_payee_world, pkg, resolver, self_point,
        star_world,
    };
    use crate::types::{EdgeContent, SlotId, Value};

    /// One instance calling itself: nothing to decompose.
    fn solo_world() -> (MetadataCache, InstanceRegistry, Manifest) {
        let mut cache = MetadataCache::new();
        let mut solo = PackageMetadata::default();
        solo.methods.insert(
            "act".into(),
            method(vec![self_point(SlotId(1), ModeExpr::Delta)]),
        );
        cache.publish_unchecked(pkg("solo"), solo);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("solo"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("solo").into(),
                method: "act".into(),
                inputs: vec![],
                evidence: Vec::new(),
                authority: None,
            }],
        };
        (cache, instances, manifest)
    }

    /// A call that stays on one shard crosses nothing, so a staged
    /// execution of it would pay for no boundary at all.
    #[test]
    fn a_single_shard_transaction_alternates_zero_times() {
        let (cache, instances, manifest) = solo_world();
        let star = classify(&manifest, &cache, &instances, &resolver());
        assert_eq!(star.crossings, 0);
    }

    /// A call reaching one instance on another shard crosses once. The
    /// depth counts the crossing rather than the shards, which is the
    /// distinction the whole quantity turns on — a chain returning to a
    /// shard it already visited has crossed twice, not once.
    #[test]
    fn a_call_to_another_shard_alternates_once() {
        let (cache, instances, manifest) = payer_payee_world();
        assert_ne!(
            resolver().shard_of(instance_of("payer").into()),
            resolver().shard_of(instance_of("payee").into()),
            "the fixture has to straddle, or the depth below proves nothing",
        );
        let star = classify(&manifest, &cache, &instances, &resolver());
        assert_eq!(star.crossings, 1);
    }

    /// A value edge is a dependency like a call is: the consumer cannot
    /// run until the producer's output exists, so a consumer on another
    /// shard is a boundary even though neither node calls the other.
    #[test]
    fn a_value_edge_across_shards_alternates_once() {
        let mut cache = MetadataCache::new();
        let mut producing = PackageMetadata::default();
        producing.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
                outputs: vec![Expr::SelfAddr],
                effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        let mut consuming = PackageMetadata::default();
        consuming.methods.insert(
            "take".into(),
            method(vec![self_point(SlotId(2), ModeExpr::Delta)]),
        );
        cache.publish_unchecked(pkg("producer"), producing);
        cache.publish_unchecked(pkg("consumer"), consuming);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("producer"));
        instances.create(&TestHasher, meta_of("consumer"));
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
                    authority: None,
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
                    authority: None,
                },
            ],
        };

        let star = classify(&manifest, &cache, &instances, &resolver());
        assert_eq!(star.crossings, 1);
    }

    /// The reservation-shaped source is the inbound leg: nothing the core
    /// produces reaches its arguments, so it can run first, and the
    /// reserve is what lets its refusal release rather than abort.
    #[test]
    fn a_reservation_shaped_source_is_an_inbound_leg() {
        let (cache, instances, manifest) = star_world(Totality::Fallible);
        let star = classify(&manifest, &cache, &instances, &resolver());
        assert_eq!(star.roles[0], Role::Inbound);
        assert_eq!(star.roles[1], Role::Core, "the venue is the core");
    }

    /// A sink whose method carries the verified mark is the outbound leg.
    /// Without the mark the same node is core — the shape alone never
    /// earns it, because what the core needs is the guarantee that
    /// nothing comes back, and only the checker can give that.
    #[test]
    fn only_a_marked_sink_is_an_outbound_leg() {
        for (totality, expected) in [
            (Totality::Fallible, Role::Core),
            (Totality::Infallible, Role::Core),
            (Totality::Total, Role::Outbound),
        ] {
            let (cache, instances, manifest) = star_world(totality);
            let star = classify(&manifest, &cache, &instances, &resolver());
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
        let (cache, instances, _) = star_world(Totality::Fallible);
        // The venue first, and the same reservation-shaped method after
        // it — its amount now the venue's output rather than a literal.
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("venue").into(),
                    method: "swap".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                    authority: None,
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
                    authority: None,
                },
            ],
        };

        let star = classify(&manifest, &cache, &instances, &resolver());
        assert_eq!(
            star.roles[1],
            Role::Core,
            "a reserve fed by an edge is not core-independent",
        );
    }

    /// Nothing crossing means one participant, so the two strategies name
    /// the same execution and the verdict is the one claiming less.
    #[test]
    fn a_single_shard_transaction_does_not_decompose() {
        let (cache, instances, manifest) = solo_world();
        let star = classify(&manifest, &cache, &instances, &resolver());
        assert_eq!(star.crossings, 0);
        assert_eq!(star.strategy, Strategy::Replicated);
    }

    /// A crossing inside the budget stages. The fixture's own depth is
    /// asserted beside the verdict, so a placement change that moved it
    /// past the budget would show up as the depth changing rather than as
    /// a verdict quietly meaning something else.
    #[test]
    fn a_crossing_within_the_budget_decomposes() {
        let (cache, instances, manifest) = payer_payee_world();
        let star = classify(&manifest, &cache, &instances, &resolver());
        assert!(star.crossings <= MAX_STAGED_DEPTH);
        assert_eq!(star.strategy, Strategy::LegLocal);
    }

    /// The budget is a refusal, not a preference: past it the settlement
    /// latency staging adds outruns the replicated work it deletes, so
    /// the deeper route runs replicated however well shaped it is.
    #[test]
    fn a_route_past_the_budget_replicates() {
        let empty = Manifest { nodes: vec![] };
        assert_eq!(
            classify_strategy(&empty, &[], MAX_STAGED_DEPTH + 1, MAX_STAGED_DEPTH + 1),
            Strategy::Replicated,
        );
        assert_eq!(
            classify_strategy(&empty, &[], MAX_STAGED_DEPTH, MAX_STAGED_DEPTH),
            Strategy::LegLocal,
            "the budget's own depth is admitted, not refused",
        );
        // The budget reads stages, not crossings: a chain that crosses
        // past the budget but only stages within it still decomposes,
        // which is exactly the single-venue swap's shape.
        assert_eq!(
            classify_strategy(&empty, &[], MAX_STAGED_DEPTH + 4, MAX_STAGED_DEPTH),
            Strategy::LegLocal,
        );
    }

    /// A leg carrying named instances replicates: the supply delta an
    /// escrow certificate attests counts amounts and cannot see which id
    /// moved, so nothing bounds a fabricated one.
    #[test]
    fn a_leg_moving_named_instances_replicates() {
        let (cache, instances, manifest) = star_world(Totality::Total);
        let fungible = classify(&manifest, &cache, &instances, &resolver());
        assert_eq!(fungible.roles[0], Role::Inbound);
        assert_eq!(fungible.strategy, Strategy::LegLocal);

        // The identical shape, with the inbound leg's value now named.
        let mut named = manifest;
        named.nodes[1].inputs = vec![NodeInput::Edge {
            source: 0,
            output: 0,
            resource: issued_by("vault"),
            content: EdgeContent::NonFungible { ids: vec![7] },
            bounds: Bounds::default(),
        }];
        let star = classify(&named, &cache, &instances, &resolver());
        assert_eq!(star.strategy, Strategy::Replicated);
    }
}
