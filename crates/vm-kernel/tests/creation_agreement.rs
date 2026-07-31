//! Declaration and execution agree on fresh keys: the effect DSL's
//! fresh-key expression and the kernel's creation context share one
//! derivation, so a routed declaration names exactly the key the kernel
//! creates.

use hyperscale_vm_effects::{
    Address, Clause, Effect, EffectTarget, Expr, GraphNode, Hash32, InstanceMeta, InstanceRegistry,
    ManifestGraph, MetadataCache, MethodSignature, Mode, ModeExpr, PackageHash, PackageMetadata,
    PrefixShardResolver, RoleId, ShardId, TargetExpr, TestHasher, Value, admit, fresh_id, route,
};
use hyperscale_vm_kernel::{CreationContext, MemoryStore, SubstateStore};

#[test]
fn a_routed_fresh_key_is_the_key_the_kernel_creates() {
    // A package whose method creates one object and inserts one collection
    // entry at a fresh sequence.
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "spawn".into(),
        MethodSignature {
            params: vec![],
            outputs: vec![],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(Expr::FreshKey { slot: 0 }),
                    mode: ModeExpr::Write,
                },
                Clause::Effect {
                    target: TargetExpr::Entry {
                        owner: Expr::SelfAddr,
                        collection: RoleId(4),
                        order: Expr::Pack {
                            hi: Box::new(Expr::Literal(Value::U64(99))),
                            lo: Box::new(Expr::FreshId { slot: 1 }),
                        },
                    },
                    mode: ModeExpr::Write,
                },
            ],
            calls: vec![],
        },
    );
    let creator = Address([0x11; 16]);
    let package_hash = PackageHash(Hash32([1; 32]));
    let mut cache = MetadataCache::new();
    cache.publish(package_hash, package);
    let mut instances = InstanceRegistry::new();
    instances.register(
        creator,
        InstanceMeta {
            package: package_hash,
            config: vec![],
        },
    );

    // Two manifest nodes so the created object comes from a non-zero node
    // index — the namespacing the derivation must carry.
    let graph = ManifestGraph {
        nodes: vec![
            GraphNode {
                target: creator,
                method: "spawn".into(),
                args: vec![],
            },
            GraphNode {
                target: creator,
                method: "spawn".into(),
                args: vec![],
            },
        ],
    };
    let admitted = admit(&graph, &cache, &instances, &TestHasher).expect("admits");
    let identity = admitted.identity();
    let routing = route(
        &admitted,
        &cache,
        &instances,
        &TestHasher,
        &PrefixShardResolver { bits: 8 },
    )
    .unwrap();
    let declared = &routing.per_shard[&ShardId(0x11)];

    // The kernel executes node 1: its creation context derives from the
    // same transaction identity, node index, and frame.
    let mut store = MemoryStore::new();
    let mut ctx = CreationContext::new(creator, identity, 1, 0);
    let created = ctx.create(&mut store, &TestHasher, vec![42]).unwrap();
    assert!(declared.contains(&Effect {
        target: EffectTarget::Point(created),
        mode: Mode::Write,
    }));

    // The entry's fresh sequence agrees the same way.
    let seq = fresh_id(&TestHasher, identity, 1, 0, 1);
    store
        .entry_write(
            creator,
            RoleId(4),
            (u128::from(99u64) << 64) | u128::from(seq),
            vec![7],
        )
        .unwrap();
    assert!(declared.contains(&Effect {
        target: EffectTarget::Entry {
            owner: creator,
            collection: RoleId(4),
            order: (u128::from(99u64) << 64) | u128::from(seq),
        },
        mode: Mode::Write,
    }));

    // Node 0's creation is a different key: the node index namespaces.
    let mut other = CreationContext::new(creator, identity, 0, 0);
    let from_node_zero = other.fresh_key(&TestHasher);
    assert_ne!(from_node_zero, created);
    assert!(declared.contains(&Effect {
        target: EffectTarget::Point(from_node_zero),
        mode: Mode::Write,
    }));
}
