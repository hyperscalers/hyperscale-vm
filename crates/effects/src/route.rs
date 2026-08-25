//! Routing: the shard projection of an admitted transaction.
//!
//! Admission's single walk evaluates every frame and lowers every call;
//! what remains here is topology. Shard resolution comes through the
//! [`ShardResolver`] seam; the beacon fold's shard trie binds there at
//! integration.

use std::collections::BTreeMap;

use hyperscale_vm_types::{Address, Effect, EffectSet};

use crate::admission::Admitted;
use crate::dsl::{Declaration, DeclaredAccess};
use crate::invoke::NodeCall;
use crate::types::ShardId;

/// Resolves an owner prefix to the shard holding it.
pub trait ShardResolver {
    /// The shard whose key space contains `owner`'s prefix.
    fn shard_of(&self, owner: Address) -> ShardId;
}

/// Test-grade resolver: a uniform trie of depth `bits`, the shard being
/// the leaf whose path is the address's top `bits` bits. Stands in for the
/// beacon fold's shard trie.
///
/// Emits the leaf's heap index `(1 << depth) | path` rather than the bare
/// path, which is what a trie leaf's identity actually is: without the
/// depth marker the root and the all-zero leaf below it — and every
/// all-zero leaf under that — would share an id. The stand-in models that
/// so a resolver swapped in behind it cannot find the seam narrower than
/// its own identities.
#[derive(Clone, Copy, Debug)]
pub struct PrefixShardResolver {
    /// The uniform trie's depth: how many leading bits of the prefix name
    /// the leaf. `0` is the root, which holds every address; values past
    /// 63 clamp, matching the depth bound a heap index can carry.
    pub bits: u8,
}

impl ShardResolver for PrefixShardResolver {
    fn shard_of(&self, owner: Address) -> ShardId {
        let depth = u32::from(self.bits.min(63));
        let bytes = owner.to_bytes();
        let head = u64::from_be_bytes(bytes[..8].try_into().expect("an address is 32 bytes"));
        // At depth zero the shift is the full width, which `checked_shr`
        // reports rather than wrapping: the root's path is empty.
        let path = head.checked_shr(64 - depth).unwrap_or(0);
        ShardId((1 << depth) | path)
    }
}

/// A routed transaction: what admission, scheduling, provisioning, and fee
/// estimation consume.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Routing {
    /// The declared effect set of every participating shard.
    pub per_shard: BTreeMap<ShardId, EffectSet>,
    /// Every evaluated frame's declaration, in preorder.
    pub frames: Vec<FrameDeclaration>,
    /// One lowered invocation per manifest node, in node order: the
    /// export to call and where each of its ABI arguments comes from.
    ///
    /// Shard-invariant, like the capability table the handle positions
    /// index into: every participant of a cross-shard transaction lowers
    /// the identical call list, and locality scopes what is *applied*
    /// rather than what is invoked.
    pub calls: Vec<NodeCall>,
    /// The transaction's whole declaration, built as the fold runs;
    /// reached through [`Routing::declaration`].
    declaration: Declaration,
}

/// One frame's contribution to the transaction's declaration.
///
/// A frame is one manifest node's signature evaluation. Frames appear in
/// [`Routing::frames`] in node order, which is the order the kernel
/// materializes capabilities in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameDeclaration {
    /// The invoking manifest node.
    pub node: u32,
    /// This frame's accesses in clause order — one entry per clause the
    /// evaluation reached, `for-each` bodies expanded in place, each
    /// carrying what its cell holds.
    ///
    /// A frame's handles occupy a contiguous run of the capability table,
    /// so a generated guest's positional parameters are this slice.
    pub ordered: Vec<DeclaredAccess>,
}

impl Routing {
    /// The participating shards, ascending.
    pub fn shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.per_shard.keys().copied()
    }

    /// The transaction's whole declaration, both views, straight from
    /// the fold.
    ///
    /// `ordered` is every frame's clauses concatenated in preorder — the
    /// order capability materialization builds its table in, and therefore
    /// the order a guest's handle parameters are in. It is deliberately not
    /// filtered by shard: the table is shard-invariant so that every
    /// participant of a cross-shard transaction agrees on which rep is
    /// which, and locality scopes what is *applied* rather than what is
    /// materialized. A fold whose reservations overflow the set is a
    /// [`RouteError::Conflict`] at `route()`, so a routing that exists
    /// has a declaration.
    #[must_use]
    pub const fn declaration(&self) -> &Declaration {
        &self.declaration
    }

    /// Append an effect no signature declared: the kernel synthesizes it
    /// from the envelope rather than from a method body — today, the
    /// nullifier write of every subintent the transaction commits.
    ///
    /// Lands after every frame's clauses, so a frame's handle slice
    /// keeps the position its signature gives it however many subintents
    /// the envelope carries. Carries no resource of its own: nothing
    /// about it is a package's declaration.
    pub(crate) fn push_kernel_effect(&mut self, shard: ShardId, effect: Effect) {
        self.per_shard
            .entry(shard)
            .or_default()
            .insert(effect)
            .expect("only reserve amounts fold, and this is a write");
        self.declaration
            .set
            .insert(effect)
            .expect("only reserve amounts fold, and this is a write");
        self.declaration.ordered.push(DeclaredAccess {
            reach: None,
            effect,
            holds: None,
        });
    }
}

/// Route an admitted transaction: project its evaluated declaration
/// onto the shard topology.
///
/// Everything else a routing carries — the frames, the lowered calls,
/// the union declaration — was computed by admission's single walk and
/// rides the [`Admitted`]; what this adds is the per-shard split, which
/// is the one thing that depends on where prefixes live. Re-routing
/// under a new epoch topology is this projection again and nothing more.
///
/// # Panics
///
/// Never: a target's every access lands on the one shard its owner
/// resolves to, so each shard's fold reaches exactly the sums and meets
/// the union declaration already folded without conflict.
#[must_use]
pub fn route(admitted: &Admitted, shards: &dyn ShardResolver) -> Routing {
    let declaration = admitted.declaration();
    let mut per_shard: BTreeMap<ShardId, EffectSet> = BTreeMap::new();
    for access in &declaration.ordered {
        per_shard
            .entry(shards.shard_of(access.effect.target.owner()))
            .or_default()
            .insert(access.effect)
            .expect("the union declaration folded these effects");
    }
    Routing {
        per_shard,
        frames: admitted.frames().to_vec(),
        calls: admitted.calls().to_vec(),
        declaration: declaration.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_vm_types::{
        Address, AddressClass, CallTarget, Effect, EffectConflict, EffectSet, EffectTarget,
        MAX_MANIFEST_NODES, Mode, PrincipalAddr,
    };

    use super::{PrefixShardResolver, Routing, ShardResolver, route};
    use crate::admission::{AdmissionError, admit};
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
    use crate::graph::{Constraint, EdgeRef, GraphArg, GraphNode, ManifestGraph};
    use crate::hash::{Hash32, TestHasher};
    use crate::instance::{InstanceMeta, ResolveError};
    use crate::invoke::CallArg;
    use crate::manifest::Bounds;
    use crate::metadata::{MetadataCache, PackageMetadata};
    use crate::publish::{AbiError, SignatureError};
    use crate::records::{ChainRecords, Records};
    use crate::signature::{AbiParam, MethodSignature, ParamType, Totality};
    use crate::test_worlds::{
        addr, instance_of, meta_of, method, payer_payee_world, pkg, resolver, resource, self_point,
    };
    use crate::types::{EdgeContent, ShardId, SlotId, Value, child_key, package_slot};
    use crate::vocabulary::CONFIG;

    const fn alice() -> PrincipalAddr {
        PrincipalAddr::new([0xAA; 31])
    }

    fn node(target: impl Into<CallTarget>, method: &str, args: Vec<GraphArg>) -> GraphNode {
        GraphNode {
            target: target.into(),
            method: method.into(),
            args,
            evidence: BTreeSet::new(),
        }
    }

    const fn edge(producer: u32, output: u32) -> GraphArg {
        GraphArg::Edge {
            edge: EdgeRef { producer, output },
            constraints: Vec::new(),
        }
    }

    fn one_node(target: impl Into<CallTarget>) -> ManifestGraph {
        ManifestGraph {
            nodes: vec![node(target, "m", vec![])],
        }
    }

    /// Admit and route in one step, for the graphs these tests are not
    /// about refusing.
    fn routed(graph: &ManifestGraph, chain: &dyn ChainRecords) -> Routing {
        let admitted = admit(graph, alice(), chain, &TestHasher).expect("admits");
        route(&admitted, &resolver())
    }

    fn point(owner: impl Into<Address>, slot: SlotId) -> EffectTarget {
        EffectTarget::Point(child_key(&TestHasher, owner, slot, &[]))
    }

    #[test]
    fn frames_carry_the_clause_order_materialization_walks() {
        let (chain, _) = payer_payee_world();
        let graph = ManifestGraph {
            nodes: vec![
                node(
                    instance_of("payer"),
                    "pay",
                    vec![
                        GraphArg::Literal(Value::Address(instance_of("payee").into())),
                        GraphArg::Literal(Value::U128(9)),
                    ],
                ),
                node(instance_of("payee"), "recv", vec![edge(0, 0)]),
            ],
        };
        let routing = routed(&graph, &chain);

        // Node order: one frame each, which is the order
        // `KernelSession::materialize` builds its capability table in, so
        // it is the order a generated guest's handle parameters are in.
        assert_eq!(
            routing
                .frames
                .iter()
                .map(|frame| frame.node)
                .collect::<Vec<_>>(),
            vec![0, 1],
        );

        // The transaction-wide declaration reaches every effect routing
        // placed on a shard and folds back to exactly that union — the
        // property a consumer building a kernel batch depends on, and the
        // one `execute_batch` rechecks before running anything.
        let declaration = routing.declaration().clone();
        let mut union = EffectSet::new();
        for set in routing.per_shard.values() {
            for effect in set.iter() {
                union.insert(effect).unwrap();
            }
        }
        assert_eq!(declaration.set, union);
        assert_eq!(
            declaration
                .ordered
                .iter()
                .map(|access| access.effect)
                .collect::<Vec<_>>(),
            vec![
                Effect {
                    target: point(instance_of("payer"), SlotId(1)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: EffectTarget::Point(child_key(
                        &TestHasher,
                        instance_of("payer"),
                        CONFIG,
                        &[],
                    )),
                    mode: Mode::Read,
                },
                Effect {
                    target: point(instance_of("payee"), SlotId(2)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: EffectTarget::Point(child_key(
                        &TestHasher,
                        instance_of("payee"),
                        CONFIG,
                        &[],
                    )),
                    mode: Mode::Read,
                },
            ],
            "each node's clauses in node order, its fence read last — \
             appended, so every clause span an ABI binding names keeps \
             the position its signature gave it"
        );
    }

    #[test]
    fn unknown_lookups_are_distinct_errors() {
        let ghost_meta = InstanceMeta {
            package: pkg("ghost"),
            config: vec![],
            salt: Hash32([8; 32]),
        };
        let a_1_4 = ghost_meta.address(&TestHasher);
        let graph = one_node(a_1_4);
        let empty = admit(&graph, alice(), &Records::new(), &TestHasher);
        assert_eq!(
            empty.err(),
            Some(AdmissionError::Resolve(ResolveError::UnknownInstance(
                a_1_4.into()
            )))
        );

        let mut ghost = Records::new();
        ghost.instances.create(&TestHasher, ghost_meta);
        let missing_pkg = admit(&graph, alice(), &ghost, &TestHasher);
        assert_eq!(
            missing_pkg.err(),
            Some(AdmissionError::Resolve(ResolveError::UnknownPackage(pkg(
                "ghost"
            ))))
        );

        // The instance resolves and its package is published; only the
        // method is missing.
        let mut chain = ghost;
        chain
            .packages
            .publish_unchecked(pkg("ghost"), PackageMetadata::default());
        let missing_method = admit(&graph, alice(), &chain, &TestHasher);
        assert_eq!(
            missing_method.err(),
            Some(AdmissionError::Resolve(ResolveError::UnknownMethod {
                package: pkg("ghost"),
                method: "m".into(),
            }))
        );
    }

    /// The effects a package's own clauses declared, with the
    /// instantiation fence's read of the target's configuration leaf
    /// dropped.
    ///
    /// Admission puts that read on every component call, so a test about
    /// what a signature declares counts what the signature wrote.
    fn own_effects(set: &EffectSet, target: impl Into<Address>) -> usize {
        let leaf = EffectTarget::Point(child_key(&TestHasher, target, CONFIG, &[]));
        set.iter().filter(|effect| effect.target != leaf).count()
    }

    #[test]
    fn a_read_declares_its_target() {
        let mut chain = Records::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert(
            "peek".into(),
            // Two of the package's own slots, so neither is the
            // configuration leaf the instantiation fence already reads —
            // which would fold into one effect and prove nothing.
            method(vec![
                self_point(package_slot(0), ModeExpr::Read),
                self_point(package_slot(1), ModeExpr::Read),
            ]),
        );
        chain.packages.publish_unchecked(pkg("oracle"), meta);
        chain.instances.create(&TestHasher, meta_of("oracle"));
        let graph = ManifestGraph {
            nodes: vec![node(instance_of("oracle"), "peek", vec![])],
        };
        let routing = routed(&graph, &chain);
        // A read declares its target like any other mode; whether the
        // target is actually there is the kernel's to refuse, since only
        // the store knows.
        let declared = routing.per_shard.values().next().unwrap();
        assert_eq!(own_effects(declared, instance_of("oracle")), 2);
        for slot in [package_slot(0), package_slot(1)] {
            assert!(declared.contains(&Effect {
                target: point(instance_of("oracle"), slot),
                mode: Mode::Read,
            }));
        }
    }

    #[test]
    fn a_graph_at_the_node_cap_admits_within_the_budget() {
        // Every node costs one evaluation, so a call-free graph at the
        // node cap must admit and route: the budget is sized from the
        // cap, and a graph one node past it is rejected for its size,
        // never for arithmetic.
        let mut chain = Records::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert("m".into(), method(vec![]));
        chain.packages.publish_unchecked(pkg("wide"), meta);
        chain.instances.create(&TestHasher, meta_of("wide"));
        let admit_at = |count: usize| {
            let graph = ManifestGraph {
                nodes: (0..count)
                    .map(|_| node(instance_of("wide"), "m", vec![]))
                    .collect(),
            };
            admit(&graph, alice(), &chain, &TestHasher)
                .map(|admitted| route(&admitted, &resolver()))
        };

        // The size at which the old budget started refusing admissible
        // manifests.
        assert!(admit_at(1_025).is_ok());
        assert!(admit_at(MAX_MANIFEST_NODES).is_ok());
        assert_eq!(
            admit_at(MAX_MANIFEST_NODES + 1).err(),
            Some(AdmissionError::TooManyNodes)
        );
    }

    #[test]
    fn folded_reserve_amounts_report_their_overflow() {
        // The effect set sums reserves on one target, so two maximal
        // declarations on the same cell leave `u128` — an admission
        // verdict, not a panic.
        let mut chain = Records::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert(
            "take".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::U128],
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotId(1),
                        material: vec![],
                    }),
                    mode: ModeExpr::Reserve(Expr::Arg(0)),
                    denomination: None,
                }],
                ..MethodSignature::default()
            },
        );
        chain.packages.publish_unchecked(pkg("vault"), meta);
        chain.instances.create(&TestHasher, meta_of("vault"));
        let take = || {
            node(
                instance_of("vault"),
                "take",
                vec![GraphArg::Literal(Value::U128(u128::MAX))],
            )
        };
        assert_eq!(
            admit(
                &ManifestGraph {
                    nodes: vec![take(), take()],
                },
                alice(),
                &chain,
                &TestHasher,
            )
            .err(),
            Some(AdmissionError::Conflict(EffectConflict::ReserveOverflow))
        );
    }

    #[test]
    fn prefix_resolver_names_the_leaf_at_its_depth() {
        // `(1 << depth) | path`: the depth marker above the prefix bits.
        assert_eq!(
            PrefixShardResolver { bits: 4 }
                .shard_of(Address::new([0xAB; 31], AddressClass::Component)),
            ShardId(0x1A)
        );
        assert_eq!(
            PrefixShardResolver { bits: 0 }
                .shard_of(Address::new([0xFF; 31], AddressClass::Component)),
            ShardId(1),
            "the root holds every address, and is a leaf like any other"
        );
        assert_eq!(
            PrefixShardResolver { bits: 16 }
                .shard_of(Address::new([0xAB; 31], AddressClass::Component)),
            ShardId(0x1_ABAB)
        );
    }

    #[test]
    fn leaves_at_different_depths_never_share_an_id() {
        // The failure a narrow id makes silent. An all-zero prefix sits in
        // the leftmost leaf at every depth, so those leaves differ only by
        // their depth marker — and past depth 15 the marker alone leaves
        // `u16`. Truncated, every one of them would read as the same
        // shard, and one shard would be credited with all their effects.
        let zeros = Address::new([0; 31], AddressClass::Component);
        let ids: Vec<ShardId> = (0..=63)
            .map(|bits| PrefixShardResolver { bits }.shard_of(zeros))
            .collect();
        let unique: BTreeSet<ShardId> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "two depths collided on one id");
        assert_eq!(ids[63], ShardId(1 << 63), "the deepest leaf fills `u64`");
        assert!(
            ids.iter().filter(|id| id.0 > u64::from(u16::MAX)).count() > 0,
            "the range past `u16` must actually be reached, or this proves nothing"
        );
    }

    #[test]
    fn a_depth_past_the_bound_clamps_rather_than_wrapping() {
        // 64 would shift the marker off the top; the resolver pins at the
        // deepest leaf a heap index can name instead.
        let deepest = PrefixShardResolver { bits: 63 }
            .shard_of(Address::new([0xAB; 31], AddressClass::Component));
        for bits in [64, 128, 255] {
            assert_eq!(
                PrefixShardResolver { bits }
                    .shard_of(Address::new([0xAB; 31], AddressClass::Component)),
                deepest
            );
        }
    }

    /// A world whose one method declares `spread` before a point clause
    /// and binds its ABI handle to the point.
    fn spreading_package(abi: Vec<AbiParam>) -> PackageMetadata {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                totality: Totality::Fallible,
                abi,
                effects: vec![
                    Clause::ForEach {
                        guard: None,
                        list: Expr::Config(0),
                        body: vec![Clause::Effect {
                            reach: None,
                            guard: None,
                            target: TargetExpr::Point(Expr::ChildKey {
                                owner: Box::new(Expr::SelfAddr),
                                slot: package_slot(0),
                                material: vec![Expr::Binding(0)],
                            }),
                            mode: ModeExpr::Write,
                            denomination: None,
                        }],
                    },
                    self_point(package_slot(1), ModeExpr::Write),
                ],
                ..MethodSignature::default()
            },
        );
        package
    }

    fn spreading_world(spread: Vec<Value>, abi: Vec<AbiParam>) -> (Records, ManifestGraph) {
        let mut chain = Records::new();
        chain
            .packages
            .publish_unchecked(pkg("spread"), spreading_package(abi));
        let spreader = chain.instances.create(
            &TestHasher,
            InstanceMeta {
                package: pkg("spread"),
                config: vec![Value::List(spread)],
                salt: Hash32([15; 32]),
            },
        );
        (chain, one_node(spreader))
    }

    /// The spreading world with a guard on the loop itself, so whether
    /// it maps over anything is a configured policy rather than the
    /// list's width.
    fn guarded_spreading_world(spread: Vec<Value>, taken: bool) -> (Records, ManifestGraph) {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                totality: Totality::Fallible,
                abi: vec![AbiParam::Handle { clause: 0, site: 0 }],
                effects: vec![Clause::ForEach {
                    guard: Some(Box::new(Expr::Config(1))),
                    list: Expr::Config(0),
                    body: vec![Clause::Effect {
                        reach: None,
                        guard: None,
                        target: TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(Expr::SelfAddr),
                            slot: package_slot(0),
                            material: vec![Expr::Binding(0)],
                        }),
                        mode: ModeExpr::Write,
                        denomination: None,
                    }],
                }],
                ..MethodSignature::default()
            },
        );
        let mut chain = Records::new();
        chain.packages.publish_unchecked(pkg("spread"), package);
        let spreader = chain.instances.create(
            &TestHasher,
            InstanceMeta {
                package: pkg("spread"),
                config: vec![Value::List(spread), Value::Bool(taken)],
                salt: Hash32([16; 32]),
            },
        );
        (chain, one_node(spreader))
    }

    #[test]
    fn a_guarded_out_loop_lends_a_site_of_none() {
        // The absence rides the argument, as it does for a handle on a
        // clause that was guarded out: the export takes its site either
        // way, and what a loop that never ran covers is nothing. A
        // refusal here would make a body that declares a conditional
        // loop uncallable exactly when the condition does not hold.
        let spread = vec![Value::U64(1), Value::U64(2)];
        let (chain, graph) = guarded_spreading_world(spread.clone(), false);
        let routing = routed(&graph, &chain);
        assert_eq!(
            routing.calls[0].args,
            vec![CallArg::Site {
                entries: Vec::new(),
            }]
        );

        let (chain, graph) = guarded_spreading_world(spread, true);
        let routing = routed(&graph, &chain);
        assert_eq!(
            routing.calls[0].args,
            vec![CallArg::Site {
                entries: vec![Some(0), Some(1)],
            }]
        );
    }

    #[test]
    fn a_handle_names_a_clause_rather_than_a_table_position() {
        // The `for-each` ahead of the point clause expands over the
        // instance's configuration, so the point's position in the table
        // moves with it while its clause index does not.
        for width in 1u64..4 {
            let spread: Vec<Value> = (0..width).map(Value::U64).collect();
            let (chain, graph) =
                spreading_world(spread, vec![AbiParam::Handle { clause: 1, site: 0 }]);
            let routing = routed(&graph, &chain);
            let CallArg::Site { ref entries } = routing.calls[0].args[0] else {
                panic!("a handle argument");
            };
            let rep = entries[0].expect("the clause was declared");
            let declaration = routing.declaration().clone();
            assert_eq!(u64::from(rep), width);
            assert_eq!(
                declaration.ordered[usize::try_from(rep).unwrap()]
                    .effect
                    .mode,
                Mode::Write,
                "the bound clause's own effect, whatever the spread's width"
            );
        }
    }

    /// A world whose one method guards its point clause on whether the
    /// instance's first configuration slot equals its second, with the
    /// clause's own verdict bound beside the handle it backs.
    fn guarded_world(left: Value, right: Value, abi: Vec<AbiParam>) -> (Records, ManifestGraph) {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                totality: Totality::Fallible,
                abi,
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: Some(Box::new(Expr::Eq(
                        Box::new(Expr::Config(0)),
                        Box::new(Expr::Config(1)),
                    ))),
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotId(1),
                        material: vec![],
                    }),
                    mode: ModeExpr::Write,
                    denomination: None,
                }],
                ..MethodSignature::default()
            },
        );
        let mut chain = Records::new();
        chain.packages.publish_unchecked(pkg("guarded"), package);
        let target = chain.instances.create(
            &TestHasher,
            InstanceMeta {
                package: pkg("guarded"),
                config: vec![left, right],
                salt: Hash32([21; 32]),
            },
        );
        (chain, one_node(target))
    }

    #[test]
    fn a_guarded_out_clause_declares_nothing_and_locks_nothing() {
        // The precision half: a method that writes one of two cells
        // declares, locks and routes to exactly the one it will write.
        let (chain, graph) = guarded_world(Value::U64(1), Value::U64(2), Vec::new());
        let routing = routed(&graph, &chain);
        assert_eq!(
            own_effects(
                &routing.declaration().clone().set,
                graph.nodes[0].target.address()
            ),
            0,
            "a guarded-out clause is out of the declared set"
        );
        assert_eq!(
            routing.shards().count(),
            1,
            "and the one shard routed to is the target's own, which the \
             instantiation fence makes a participant of every call"
        );

        // The same signature over a configuration its guard holds for.
        let (chain, graph) = guarded_world(Value::U64(1), Value::U64(1), Vec::new());
        let routing = routed(&graph, &chain);
        assert_eq!(
            own_effects(
                &routing.declaration().clone().set,
                graph.nodes[0].target.address()
            ),
            1
        );
    }

    #[test]
    fn a_guarded_out_handle_is_absent_rather_than_unbindable() {
        // An export's parameter list is a function of its signature and
        // cannot lose a parameter to a branch, so the guest is handed a
        // handle that answers nothing — carrying the type routing is the
        // last thing to know, beside the verdict that says so.
        let abi = vec![AbiParam::Handle { clause: 0, site: 0 }, AbiParam::Guard(0)];
        let (chain, graph) = guarded_world(Value::U64(1), Value::U64(2), abi.clone());
        let routing = routed(&graph, &chain);
        assert_eq!(
            routing.calls[0].args,
            vec![
                CallArg::Site {
                    entries: vec![None]
                },
                CallArg::Bool(false)
            ]
        );

        let (chain, graph) = guarded_world(Value::U64(1), Value::U64(1), abi);
        let routing = routed(&graph, &chain);
        assert!(matches!(
            routing.calls[0].args[0],
            CallArg::Site { ref entries } if entries == &[Some(0)]
        ));
        assert_eq!(routing.calls[0].args[1], CallArg::Bool(true));
    }

    #[test]
    fn a_guard_inside_a_loop_body_declares_per_element() {
        // Clauses land in whatever scope encloses them, so a guard
        // written inside a `for-each` is judged once per element against
        // that element's own binding — and the loop's own verdict is the
        // top-level one, which is the only one an ABI binding can name.
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                totality: Totality::Fallible,
                effects: vec![Clause::ForEach {
                    guard: None,
                    list: Expr::Config(0),
                    body: vec![Clause::Effect {
                        reach: None,
                        guard: Some(Box::new(Expr::Eq(
                            Box::new(Expr::Binding(0)),
                            Box::new(Expr::Literal(Value::U64(2))),
                        ))),
                        target: TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(Expr::SelfAddr),
                            slot: SlotId(9),
                            material: vec![Expr::Binding(0)],
                        }),
                        mode: ModeExpr::Delta,
                        denomination: None,
                    }],
                }],
                ..MethodSignature::default()
            },
        );
        let mut chain = Records::new();
        chain.packages.publish_unchecked(pkg("looped"), package);
        let target = chain.instances.create(
            &TestHasher,
            InstanceMeta {
                package: pkg("looped"),
                config: vec![Value::List(vec![
                    Value::U64(1),
                    Value::U64(2),
                    Value::U64(3),
                ])],
                salt: Hash32([22; 32]),
            },
        );
        let routing = routed(&one_node(target), &chain);
        let declaration = routing.declaration().clone();
        assert_eq!(
            own_effects(&declaration.set, target),
            1,
            "one of three elements satisfies the guard"
        );
    }

    #[test]
    fn a_guard_binding_on_an_unguarded_clause_is_refused() {
        // Its verdict is the constant true, which no export needs told.
        // Refused at the cache door, so no fold ever sees the binding.
        let refusal = MetadataCache::new()
            .publish(pkg("spread"), spreading_package(vec![AbiParam::Guard(1)]))
            .expect_err("an unguarded clause has no verdict to bind");
        assert!(
            matches!(
                refusal.source,
                SignatureError::Abi(AbiError::UnguardedClause { clause: 1, .. })
            ),
            "unexpected refusal: {refusal:?}"
        );
    }

    #[test]
    fn a_handle_on_a_site_the_loop_does_not_declare_is_refused() {
        // A `for-each` expands over the target's creation-fixed
        // configuration, and one parameter covers a whole site of it —
        // so a handle on the loop's own site is a binding like any
        // other, whatever width the configuration gives it.
        MetadataCache::new()
            .publish(
                pkg("spread"),
                spreading_package(vec![AbiParam::Handle { clause: 0, site: 0 }]),
            )
            .expect("a site of the loop backs a handle");

        // What is left to refuse is a site the loop's body does not
        // declare. Judged on the signature at the cache door, before any
        // evaluation reaches the spread: what the body declares is the
        // signature's answer whatever the configuration says.
        let refusal = MetadataCache::new()
            .publish(
                pkg("spread"),
                spreading_package(vec![AbiParam::Handle { clause: 0, site: 1 }]),
            )
            .expect_err("the loop declares no second site");
        assert!(
            matches!(
                refusal.source,
                SignatureError::Abi(AbiError::NotALoopedAccess {
                    clause: 0,
                    site: 1,
                    ..
                })
            ),
            "unexpected refusal: {refusal:?}"
        );
    }

    #[test]
    fn a_derived_judgment_crosses_as_a_flag() {
        // A predicate is evaluated once, by admission, and the guest
        // reads the answer rather than the comparison — the same flag a
        // guarded clause's verdict crosses as, so the two copies of one
        // condition a rebuilt judgment would leave never exist.
        let spread = vec![Value::U64(1)];
        let judgment = AbiParam::Derived(Expr::Eq(
            Box::new(Expr::Config(0)),
            Box::new(Expr::Config(0)),
        ));
        let (chain, graph) = spreading_world(spread, vec![judgment]);
        let routing = admit(&graph, alice(), &chain, &TestHasher).expect("the judgment binds");
        assert_eq!(routing.calls()[0].args[0], CallArg::Bool(true));
    }

    #[test]
    fn a_bucket_projection_types_its_edge_and_cell_shape() {
        // A producer whose output projection is a non-fungible bucket:
        // the lowered call frames its cell as the id list the
        // declaration named, and the consumer's bound resolves at it.
        let ids = vec![3, 9];
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "take".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::NfBucket],
                abi: vec![AbiParam::Bucket(0)],
                effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
                outputs: vec![Expr::Literal(Value::Bucket {
                    resource: resource(0xE1),
                    content: EdgeContent::NonFungible { ids },
                })],
                ..MethodSignature::default()
            },
        );
        let mut chain = Records::new();
        chain.packages.publish_unchecked(pkg("nf"), package);
        chain.instances.create(&TestHasher, meta_of("nf"));
        let graph = ManifestGraph {
            nodes: vec![
                node(instance_of("nf"), "make", vec![]),
                node(instance_of("nf"), "take", vec![edge(0, 0)]),
            ],
        };
        let routing = routed(&graph, &chain);
        assert_eq!(
            routing.calls[0].outputs,
            vec![EdgeContent::NonFungible { ids: vec![3, 9] }]
        );
        let edge = &routing.calls[1].edges[0];
        assert_eq!((edge.source, edge.output), (0, 0));
    }

    #[test]
    fn a_bucket_binding_names_the_edge_its_parameter_carries() {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "take".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::Bucket, ParamType::Bucket],
                abi: vec![AbiParam::Bucket(1)],
                effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
                outputs: vec![
                    Expr::Literal(Value::Address(resource(0xE1).address())),
                    Expr::Literal(Value::Address(resource(0xE1).address())),
                ],
                ..MethodSignature::default()
            },
        );
        let mut chain = Records::new();
        chain.packages.publish_unchecked(pkg("edges"), package);
        chain.instances.create(&TestHasher, meta_of("edges"));
        let graph = ManifestGraph {
            nodes: vec![
                node(instance_of("edges"), "make", vec![]),
                node(
                    instance_of("edges"),
                    "take",
                    vec![
                        edge(0, 0),
                        GraphArg::Edge {
                            edge: EdgeRef {
                                producer: 0,
                                output: 1,
                            },
                            constraints: vec![Constraint::MinAmount(7)],
                        },
                    ],
                ),
            ],
        };
        let routing = routed(&graph, &chain);
        assert_eq!(
            routing.calls[1].args[0],
            CallArg::Bucket {
                source: 0,
                output: 1
            },
            "a bucket argument carries the producer's output slot, not just the producer"
        );
        assert_eq!(
            routing.calls[1].edges[1].bounds,
            Bounds {
                min: Some(7),
                max: None,
            },
            "the consumed edge carries its signed bound to the walk"
        );
    }

    /// A world whose `forward` consumes a bucket without reading its
    /// amount, plus a producer to feed it.
    fn forwarding_world() -> (Records, ManifestGraph) {
        let mut router = PackageMetadata::default();
        router.methods.insert(
            "forward".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::Bucket],
                // Nothing in the ABI carries the bucket: the method
                // consumes the edge without reading what crossed.
                abi: vec![AbiParam::Handle { clause: 0, site: 0 }],
                effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        router.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
                outputs: vec![Expr::Literal(Value::Address(resource(0xE1).address()))],
                ..MethodSignature::default()
            },
        );
        let mut chain = Records::new();
        chain.packages.publish_unchecked(pkg("router"), router);
        chain.instances.create(&TestHasher, meta_of("router"));
        let graph = ManifestGraph {
            nodes: vec![
                node(instance_of("router"), "make", vec![]),
                node(
                    instance_of("router"),
                    "forward",
                    vec![GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        constraints: vec![Constraint::MinAmount(42)],
                    }],
                ),
            ],
        };
        (chain, graph)
    }

    #[test]
    fn a_forwarded_bucket_still_carries_its_edge_bound() {
        // The bound belongs to the edge, not to the argument list. A
        // method that consumes its funds without reading them carries no
        // bucket in its own ABI — and the signer's bound is owed a check
        // all the same, at the node where the edge resolves.
        let (chain, graph) = forwarding_world();
        let routing = routed(&graph, &chain);
        let call = &routing.calls[1];
        assert!(
            !call
                .args
                .iter()
                .any(|arg| matches!(arg, CallArg::Bucket { .. })),
            "the consuming method's own ABI carries no bucket"
        );
        assert_eq!(
            call.edges[0].bounds,
            Bounds {
                min: Some(42),
                max: None,
            }
        );
    }

    /// A declaration bounds what execution may touch; nothing about that
    /// bounds what a declaration may claim, unless this does.
    #[test]
    fn a_frame_cannot_declare_against_another_prefix() {
        let victim = addr(0x99);
        let foreign = |owner: Expr| {
            let mut package = PackageMetadata::default();
            package.methods.insert(
                "reach".into(),
                MethodSignature {
                    totality: Totality::Fallible,
                    params: vec![ParamType::Address],
                    effects: vec![Clause::Effect {
                        reach: None,
                        guard: None,
                        target: TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(owner),
                            slot: SlotId(1),
                            material: vec![],
                        }),
                        mode: ModeExpr::Delta,
                        denomination: None,
                    }],
                    ..MethodSignature::default()
                },
            );
            let mut chain = Records::new();
            chain.packages.publish_unchecked(pkg("reacher"), package);
            chain.instances.create(&TestHasher, meta_of("reacher"));
            let graph = ManifestGraph {
                nodes: vec![node(
                    instance_of("reacher"),
                    "reach",
                    vec![GraphArg::Literal(Value::Address(victim))],
                )],
            };
            admit(&graph, alice(), &chain, &TestHasher)
        };

        // Every way a frame can name somebody else: what its caller
        // passed, and what it holds as a literal.
        for owner in [Expr::Arg(0), Expr::Literal(Value::Address(victim))] {
            let error = foreign(owner).expect_err("a foreign prefix is not a frame's to declare");
            assert!(
                matches!(
                    error,
                    AdmissionError::ForeignDeclaration { node: 0, ref owner, .. } if *owner == victim
                ),
                "unexpected refusal: {error:?}"
            );
        }

        // Its own prefix is the admitted case, so what bites is whose
        // cells the clause names and not the shape of the declaration.
        assert!(foreign(Expr::SelfAddr).is_ok());
    }

    #[test]
    fn a_malformed_binding_refuses_at_the_door() {
        // The cache door is where the composed check runs, so a binding
        // nothing can honour never reaches a fold — there is no cached
        // package for a call to resolve against.
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::Bucket],
                abi: vec![AbiParam::Bucket(0), AbiParam::Bucket(0)],
                effects: vec![self_point(package_slot(0), ModeExpr::Write)],
                ..MethodSignature::default()
            },
        );
        let refusal = MetadataCache::new()
            .publish(pkg("bad"), package)
            .expect_err("a malformed binding cannot be published");
        assert_eq!(refusal.method, "m");
        assert!(
            matches!(refusal.source, SignatureError::Abi(_)),
            "unexpected refusal: {refusal:?}"
        );
    }
}
