//! Routing: the shard projection of an admitted transaction.
//!
//! Admission's single walk evaluates every frame and lowers every call;
//! what remains here is topology. Shard resolution comes through the
//! [`ShardResolver`] seam; the beacon fold's shard trie binds there at
//! integration.

use std::collections::BTreeMap;

use hyperscale_vm_types::{Address, EffectSet};

use crate::admission::Admitted;
use crate::dsl::DeclaredAccess;
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

/// One frame's contribution to the transaction's declaration.
///
/// A frame is one manifest node's signature evaluation. Frames appear in
/// [`Admitted::frames`](crate::Admitted::frames) in node order, which is
/// the order the kernel
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

/// Project a declaration onto a shard topology: each target's accesses
/// grouped under the shard its owner resolves to.
///
/// Nothing in the protocol asks this. A participant re-filters the whole
/// effect set through its own `OwnerSet` rather than being handed a
/// slice, and which shards a transaction *touches* is answered by the
/// star classifier, which places manifest nodes rather than effects. It
/// is here for the tests that exercise sharded shapes under a resolver
/// with bits to spare.
///
/// # Panics
///
/// Never: a target's every access lands on the one shard its owner
/// resolves to, so each shard's fold reaches exactly the sums the union
/// declaration already folded without conflict.
#[must_use]
pub fn per_shard(admitted: &Admitted, shards: &dyn ShardResolver) -> BTreeMap<ShardId, EffectSet> {
    let declaration = admitted.declaration();
    let mut out: BTreeMap<ShardId, EffectSet> = BTreeMap::new();
    for access in &declaration.ordered {
        out.entry(shards.shard_of(access.effect.target.owner()))
            .or_default()
            .insert_from(access.effect, &declaration.set)
            .expect("the union declaration folded these effects");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use hyperscale_hbor::{Capped, Name};
    use hyperscale_vm_types::{
        Address, AddressClass, CallTarget, Effect, EffectConflict, EffectSet, EffectTarget,
        MAX_MANIFEST_NODES, Mode, Moves, NetworkId, PrincipalAddr,
    };

    use super::{Admitted, PrefixShardResolver, ShardResolver, per_shard};
    use crate::admission::AdmissionError;
    use crate::cells::{nullifier_expiry_ms, nullifier_key};
    use crate::dsl::{Clause, Expr, ModeExpr, SlotRef, TargetExpr};
    use crate::graph::{Constraint, EdgeRef, GraphArg, GraphNode, ManifestGraph};
    use crate::hash::{Hash32, Hasher, TestHasher};
    use crate::instance::{InstanceMeta, ResolveError};
    use crate::intent::{Intent, IntentHeader, IntentTree, admit_tree};
    use crate::invoke::CallArg;
    use crate::manifest::Bounds;
    use crate::metadata::{MetadataCache, PackageMetadata, PublishRefusal};
    use crate::publish::{AbiError, SignatureError};
    use crate::records::{ChainRecords, Records};
    use crate::signature::{AbiParam, MethodSignature, ParamType};
    use crate::test_worlds::{
        addr, instance_of, meta_of, method, payer_payee_world, pkg, resolver, resource, self_point,
    };
    use crate::types::{EdgeContent, ShardId, SlotId, Value, child_key, package_slot};
    use crate::vocabulary::{AUTH, CONFIG};

    const fn alice() -> PrincipalAddr {
        PrincipalAddr::new([0xAA; 31])
    }

    /// Any window; nothing here validates one against a clock.
    const HEADER: IntentHeader = IntentHeader {
        network: NetworkId(242),
        validity_start_ms: 0,
        validity_end_ms: 3_600_000,
        discriminator: 0,
    };

    /// Admit `graph` as a tree of one leaf acting as `account`.
    fn admit_leaf(
        graph: &ManifestGraph,
        account: PrincipalAddr,
        chain: &dyn ChainRecords,
        hasher: &dyn Hasher,
    ) -> Result<Admitted, AdmissionError> {
        let tree = IntentTree::of_one(Intent::leaf(HEADER, account, graph.clone()));
        admit_tree(&tree, tree.hash(hasher), chain, hasher)
    }

    fn node(target: impl Into<CallTarget>, method: &str, args: Vec<GraphArg>) -> GraphNode {
        GraphNode {
            target: target.into(),
            method: method.into(),
            args,
            evidence: Capped::default(),
        }
    }

    const fn edge(producer: u32, output: u32) -> GraphArg {
        GraphArg::edge(EdgeRef { producer, output }, Vec::new())
    }

    fn one_node(target: impl Into<CallTarget>) -> ManifestGraph {
        ManifestGraph {
            nodes: Capped::new(vec![node(target, "m", vec![])]).unwrap(),
        }
    }

    /// Admit, for the graphs these tests are not about refusing.
    fn routed(graph: &ManifestGraph, chain: &dyn ChainRecords) -> Admitted {
        admit_leaf(graph, alice(), chain, &TestHasher).expect("admits")
    }

    /// The corpus resolver's projection of an admitted declaration.
    fn sets(admitted: &Admitted) -> BTreeMap<ShardId, EffectSet> {
        per_shard(admitted, &resolver())
    }

    fn point(owner: impl Into<Address>, slot: SlotId) -> EffectTarget {
        EffectTarget::Point(child_key(&TestHasher, owner, slot, &[]))
    }

    #[test]
    fn frames_carry_the_clause_order_materialization_walks() {
        let (chain, _) = payer_payee_world();
        let graph = ManifestGraph {
            nodes: Capped::new(vec![
                node(
                    instance_of("payer"),
                    "pay",
                    vec![
                        GraphArg::Literal(Value::Address(instance_of("payee").into())),
                        GraphArg::Literal(Value::U128(9)),
                    ],
                ),
                node(instance_of("payee"), "recv", vec![edge(0, 0)]),
            ])
            .unwrap(),
        };
        let admitted = routed(&graph, &chain);

        // Node order: one frame each, which is the order
        // `KernelSession::materialize` builds its capability table in, so
        // it is the order a generated guest's handle parameters are in.
        assert_eq!(
            admitted
                .frames()
                .iter()
                .map(|frame| frame.node)
                .collect::<Vec<_>>(),
            vec![0, 1],
        );

        // The transaction-wide declaration reaches every effect routing
        // placed on a shard and folds back to exactly that union — the
        // property a consumer building a kernel batch depends on, and the
        // one `execute_batch` rechecks before running anything.
        let declaration = admitted.declaration().clone();
        let mut union = EffectSet::new();
        for set in sets(&admitted).values() {
            for effect in set.iter() {
                union
                    .insert_bounded(effect, set.width_of(&effect.target))
                    .unwrap();
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
                    mode: Mode::Delta { moves: Moves::Both },
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
                    mode: Mode::Delta { moves: Moves::Both },
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
                // The intent's sign-in, which is admission's own and no
                // clause's: one read of the account's rule cell, beside
                // the condition that judges it.
                Effect {
                    target: EffectTarget::Point(child_key(
                        &TestHasher,
                        alice().address(),
                        AUTH,
                        &[],
                    )),
                    mode: Mode::Read,
                },
                // And the intent's nullifier creation, the kernel's own,
                // folded in after every frame.
                Effect {
                    target: EffectTarget::Point(nullifier_key(
                        &TestHasher,
                        alice(),
                        Intent::leaf(HEADER, alice(), graph).hash(&TestHasher),
                        nullifier_expiry_ms(&HEADER),
                    )),
                    mode: Mode::Write { moves: Moves::Both },
                },
            ],
            "each node's clauses in node order, its fence read last — \
             appended, so every clause span an ABI binding names keeps \
             the position its signature gave it, the sign-in after \
             every frame, and the nullifier last"
        );
    }

    #[test]
    fn unknown_lookups_are_distinct_errors() {
        let ghost_meta = InstanceMeta {
            package: pkg("ghost"),
            config: Capped::empty(),
            salt: Hash32([8; 32]),
        };
        let a_1_4 = ghost_meta.address(&TestHasher);
        let graph = one_node(a_1_4);
        let empty = admit_leaf(&graph, alice(), &Records::new(), &TestHasher);
        assert_eq!(
            empty.err(),
            Some(AdmissionError::Resolve(ResolveError::UnknownInstance(
                a_1_4.into()
            )))
        );

        let mut ghost = Records::new();
        ghost.instances.create(&TestHasher, ghost_meta);
        let missing_pkg = admit_leaf(&graph, alice(), &ghost, &TestHasher);
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
        let missing_method = admit_leaf(&graph, alice(), &chain, &TestHasher);
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
    /// The effects `target` declares of its own, its instantiation fence
    /// aside. Owner-keyed, so what admission injects under another
    /// prefix — a signing account's rule cell — is somebody else's and
    /// not counted here.
    fn own_effects(set: &EffectSet, target: impl Into<Address>) -> usize {
        let target = target.into();
        let fence = EffectTarget::Point(child_key(&TestHasher, target, CONFIG, &[]));
        set.iter()
            .filter(|effect| effect.target.owner() == target && effect.target != fence)
            .count()
    }

    #[test]
    fn a_read_declares_its_target() {
        let mut chain = Records::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert(
            Name::declared("peek"),
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
            nodes: Capped::new(vec![node(instance_of("oracle"), "peek", vec![])]).unwrap(),
        };
        let admitted = routed(&graph, &chain);
        // A read declares its target like any other mode; whether the
        // target is actually there is the kernel's to refuse, since only
        // the store knows.
        let projected = sets(&admitted);
        let declared = projected.values().next().unwrap();
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
        meta.methods.insert(Name::declared("m"), method(vec![]));
        chain.packages.publish_unchecked(pkg("wide"), meta);
        chain.instances.create(&TestHasher, meta_of("wide"));
        let admit_at = |count: usize| {
            let graph = ManifestGraph {
                nodes: (0..count)
                    .map(|_| node(instance_of("wide"), "m", vec![]))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            };
            admit_leaf(&graph, alice(), &chain, &TestHasher).map(|admitted| sets(&admitted))
        };

        // A size well inside the cap, and the cap itself. One past it is
        // not a graph the type can hold, so admission never sees one.
        assert!(admit_at(1_025).is_ok());
        assert!(admit_at(MAX_MANIFEST_NODES).is_ok());
        assert!(
            Capped::<Vec<GraphNode>, MAX_MANIFEST_NODES>::new(
                (0..=MAX_MANIFEST_NODES)
                    .map(|_| node(instance_of("wide"), "m", vec![]))
                    .collect()
            )
            .is_err()
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
            Name::declared("take"),
            MethodSignature {
                declines: true,
                params: vec![ParamType::U128],
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotRef::Fixed(SlotId(1)),
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
            admit_leaf(
                &ManifestGraph {
                    nodes: Capped::new(vec![take(), take()]).unwrap(),
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
            .collect::<Vec<_>>();
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
            Name::declared("m"),
            MethodSignature {
                declines: true,
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
                                slot: SlotRef::Fixed(package_slot(0)),
                                material: vec![Expr::Binding(0)],
                            }),
                            mode: ModeExpr::Write { moves: Moves::Both },
                            denomination: None,
                        }],
                    },
                    self_point(package_slot(1), ModeExpr::Write { moves: Moves::Both }),
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
                config: Capped::new(vec![Value::List(spread)]).unwrap(),
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
            Name::declared("m"),
            MethodSignature {
                declines: true,
                abi: vec![AbiParam::Handle { clause: 0, site: 0 }],
                effects: vec![Clause::ForEach {
                    guard: Some(Box::new(Expr::Config(1))),
                    list: Expr::Config(0),
                    body: vec![Clause::Effect {
                        reach: None,
                        guard: None,
                        target: TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(Expr::SelfAddr),
                            slot: SlotRef::Fixed(package_slot(0)),
                            material: vec![Expr::Binding(0)],
                        }),
                        mode: ModeExpr::Write { moves: Moves::Both },
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
                config: Capped::new(vec![Value::List(spread), Value::Bool(taken)]).unwrap(),
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
        let admitted = routed(&graph, &chain);
        assert_eq!(
            admitted.calls()[0].args,
            vec![CallArg::Site {
                entries: Vec::new(),
            }]
        );

        let (chain, graph) = guarded_spreading_world(spread, true);
        let admitted = routed(&graph, &chain);
        assert_eq!(
            admitted.calls()[0].args,
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
            let admitted = routed(&graph, &chain);
            let CallArg::Site { ref entries } = admitted.calls()[0].args[0] else {
                panic!("a handle argument");
            };
            let rep = entries[0].expect("the clause was declared");
            let declaration = admitted.declaration().clone();
            assert_eq!(u64::from(rep), width);
            assert_eq!(
                declaration.ordered[usize::try_from(rep).unwrap()]
                    .effect
                    .mode,
                Mode::Write { moves: Moves::Both },
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
            Name::declared("m"),
            MethodSignature {
                declines: true,
                abi,
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: Some(Box::new(Expr::Eq(
                        Box::new(Expr::Config(0)),
                        Box::new(Expr::Config(1)),
                    ))),
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotRef::Fixed(SlotId(1)),
                        material: vec![],
                    }),
                    mode: ModeExpr::Write { moves: Moves::Both },
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
                config: Capped::new(vec![left, right]).unwrap(),
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
        let admitted = routed(&graph, &chain);
        assert_eq!(
            own_effects(
                &admitted.declaration().clone().set,
                graph.nodes[0].target.address()
            ),
            0,
            "a guarded-out clause is out of the declared set"
        );
        assert_eq!(
            sets(&admitted).len(),
            2,
            "the target's own shard, which the instantiation fence makes \
             a participant of every call, and the signing account's, \
             whose rule cell the sign-in reads"
        );

        // The same signature over a configuration its guard holds for.
        let (chain, graph) = guarded_world(Value::U64(1), Value::U64(1), Vec::new());
        let admitted = routed(&graph, &chain);
        assert_eq!(
            own_effects(
                &admitted.declaration().clone().set,
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
        let admitted = routed(&graph, &chain);
        assert_eq!(
            admitted.calls()[0].args,
            vec![
                CallArg::Site {
                    entries: vec![None]
                },
                CallArg::Bool(false)
            ]
        );

        let (chain, graph) = guarded_world(Value::U64(1), Value::U64(1), abi);
        let admitted = routed(&graph, &chain);
        assert!(matches!(
            admitted.calls()[0].args[0],
            CallArg::Site { ref entries } if entries == &[Some(0)]
        ));
        assert_eq!(admitted.calls()[0].args[1], CallArg::Bool(true));
    }

    #[test]
    fn a_guard_inside_a_loop_body_declares_per_element() {
        // Clauses land in whatever scope encloses them, so a guard
        // written inside a `for-each` is judged once per element against
        // that element's own binding — and the loop's own verdict is the
        // top-level one, which is the only one an ABI binding can name.
        let mut package = PackageMetadata::default();
        package.methods.insert(
            Name::declared("m"),
            MethodSignature {
                declines: true,
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
                            slot: SlotRef::Fixed(SlotId(9)),
                            material: vec![Expr::Binding(0)],
                        }),
                        mode: ModeExpr::Delta { moves: Moves::Both },
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
                config: Capped::new(vec![Value::List(vec![
                    Value::U64(1),
                    Value::U64(2),
                    Value::U64(3),
                ])])
                .unwrap(),
                salt: Hash32([22; 32]),
            },
        );
        let admitted = routed(&one_node(target), &chain);
        let declaration = admitted.declaration().clone();
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
                refusal,
                PublishRefusal::Method {
                    source: SignatureError::Abi(AbiError::UnguardedClause { clause: 1, .. }),
                    ..
                }
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
                refusal,
                PublishRefusal::Method {
                    source: SignatureError::Abi(AbiError::NotALoopedAccess {
                        clause: 0,
                        site: 1,
                        ..
                    }),
                    ..
                }
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
        let admitted =
            admit_leaf(&graph, alice(), &chain, &TestHasher).expect("the judgment binds");
        assert_eq!(admitted.calls()[0].args[0], CallArg::Bool(true));
    }

    #[test]
    fn a_bucket_projection_types_its_edge_and_cell_shape() {
        // A producer whose output projection is a non-fungible bucket:
        // the lowered call frames its cell as the id list the
        // declaration named, and the consumer's bound resolves at it.
        let ids = vec![3, 9];
        let mut package = PackageMetadata::default();
        package.methods.insert(
            Name::declared("take"),
            MethodSignature {
                declines: true,
                params: vec![ParamType::NfBucket],
                abi: vec![AbiParam::Bucket(0)],
                effects: vec![self_point(
                    SlotId(1),
                    ModeExpr::Delta { moves: Moves::Both },
                )],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            Name::declared("make"),
            MethodSignature {
                declines: true,
                outputs: vec![Expr::Literal(Value::Bucket {
                    resource: resource(0xE1),
                    content: EdgeContent::NonFungible {
                        ids: Capped::new(ids).unwrap(),
                    },
                })],
                ..MethodSignature::default()
            },
        );
        let mut chain = Records::new();
        chain.packages.publish_unchecked(pkg("nf"), package);
        chain.instances.create(&TestHasher, meta_of("nf"));
        let graph = ManifestGraph {
            nodes: Capped::new(vec![
                node(instance_of("nf"), "make", vec![]),
                node(instance_of("nf"), "take", vec![edge(0, 0)]),
            ])
            .unwrap(),
        };
        let admitted = routed(&graph, &chain);
        assert_eq!(
            admitted.calls()[0].outputs,
            vec![EdgeContent::NonFungible {
                ids: Capped::new(vec![3, 9]).unwrap()
            }]
        );
        let edge = &admitted.calls()[1].edges[0];
        assert_eq!((edge.source, edge.output), (0, 0));
    }

    #[test]
    fn a_bucket_binding_names_the_edge_its_parameter_carries() {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            Name::declared("take"),
            MethodSignature {
                declines: true,
                params: vec![ParamType::Bucket, ParamType::Bucket],
                abi: vec![AbiParam::Bucket(1)],
                effects: vec![self_point(
                    SlotId(1),
                    ModeExpr::Delta { moves: Moves::Both },
                )],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            Name::declared("make"),
            MethodSignature {
                declines: true,
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
            nodes: Capped::new(vec![
                node(instance_of("edges"), "make", vec![]),
                node(
                    instance_of("edges"),
                    "take",
                    vec![
                        edge(0, 0),
                        GraphArg::edge(
                            EdgeRef {
                                producer: 0,
                                output: 1,
                            },
                            vec![Constraint::MinAmount(7)],
                        ),
                    ],
                ),
            ])
            .unwrap(),
        };
        let admitted = routed(&graph, &chain);
        assert_eq!(
            admitted.calls()[1].args[0],
            CallArg::Bucket {
                source: 0,
                output: 1
            },
            "a bucket argument carries the producer's output slot, not just the producer"
        );
        assert_eq!(
            admitted.calls()[1].edges[1].bounds,
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
            Name::declared("forward"),
            MethodSignature {
                declines: true,
                params: vec![ParamType::Bucket],
                // Nothing in the ABI carries the bucket: the method
                // consumes the edge without reading what crossed.
                abi: vec![AbiParam::Handle { clause: 0, site: 0 }],
                effects: vec![self_point(
                    SlotId(1),
                    ModeExpr::Delta { moves: Moves::Both },
                )],
                ..MethodSignature::default()
            },
        );
        router.methods.insert(
            Name::declared("make"),
            MethodSignature {
                declines: true,
                outputs: vec![Expr::Literal(Value::Address(resource(0xE1).address()))],
                ..MethodSignature::default()
            },
        );
        let mut chain = Records::new();
        chain.packages.publish_unchecked(pkg("router"), router);
        chain.instances.create(&TestHasher, meta_of("router"));
        let graph = ManifestGraph {
            nodes: Capped::new(vec![
                node(instance_of("router"), "make", vec![]),
                node(
                    instance_of("router"),
                    "forward",
                    vec![GraphArg::edge(
                        EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        vec![Constraint::MinAmount(42)],
                    )],
                ),
            ])
            .unwrap(),
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
        let admitted = routed(&graph, &chain);
        let call = &admitted.calls()[1];
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
                Name::declared("reach"),
                MethodSignature {
                    declines: true,
                    params: vec![ParamType::Address],
                    effects: vec![Clause::Effect {
                        reach: None,
                        guard: None,
                        target: TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(owner),
                            slot: SlotRef::Fixed(SlotId(1)),
                            material: vec![],
                        }),
                        mode: ModeExpr::Delta { moves: Moves::Both },
                        denomination: None,
                    }],
                    ..MethodSignature::default()
                },
            );
            let mut chain = Records::new();
            chain.packages.publish_unchecked(pkg("reacher"), package);
            chain.instances.create(&TestHasher, meta_of("reacher"));
            let graph = ManifestGraph {
                nodes: Capped::new(vec![node(
                    instance_of("reacher"),
                    "reach",
                    vec![GraphArg::Literal(Value::Address(victim))],
                )])
                .unwrap(),
            };
            admit_leaf(&graph, alice(), &chain, &TestHasher)
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
            Name::declared("m"),
            MethodSignature {
                declines: true,
                params: vec![ParamType::Bucket],
                abi: vec![AbiParam::Bucket(0), AbiParam::Bucket(0)],
                effects: vec![self_point(
                    package_slot(0),
                    ModeExpr::Write { moves: Moves::Both },
                )],
                ..MethodSignature::default()
            },
        );
        let refusal = MetadataCache::new()
            .publish(pkg("bad"), package)
            .expect_err("a malformed binding cannot be published");
        assert!(
            matches!(
                &refusal,
                PublishRefusal::Method {
                    method,
                    source: SignatureError::Abi(_),
                } if method == "m"
            ),
            "unexpected refusal: {refusal:?}"
        );
    }
}
