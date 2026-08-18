//! Declaration and execution agree on fresh keys: the effect DSL's
//! fresh-key expression and the kernel's creation context share one
//! derivation, so a routed declaration names exactly the key the kernel
//! creates.

use std::collections::BTreeSet;

use hyperscale_vm_effects::{
    Clause, Effect, EffectTarget, Expr, GraphNode, Hash32, InstanceMeta, InstanceRegistry,
    ManifestGraph, MetadataCache, MethodSignature, Mode, ModeExpr, PackageHash, PackageMetadata,
    PrefixShardResolver, Presence, PrincipalAddr, ShardResolver, SlotId, TargetExpr, TestHasher,
    Totality, Value, admit, collection_id, fresh_id, route,
};
use hyperscale_vm_kernel::{CreationContext, MemoryStore, WorkingStore};

/// A package whose one method creates one object and inserts one
/// collection entry at a fresh sequence.
fn spawner() -> PackageMetadata {
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "spawn".into(),
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(Expr::FreshKey { slot: 0 }),
                    mode: declared_write(),
                    denomination: None,
                },
                Clause::Effect {
                    target: TargetExpr::Entry {
                        owner: Expr::SelfAddr,
                        collection: SlotId(4),
                        material: vec![],
                        order: Expr::Pack {
                            hi: Box::new(Expr::Literal(Value::U64(99))),
                            lo: Box::new(Expr::FreshId { slot: 1 }),
                        },
                    },
                    mode: declared_write(),
                    denomination: None,
                },
            ],
            ..MethodSignature::default()
        },
    );
    package
}

/// An ordinary declared write: on a leaf that may or may not be there.
const fn declared_write() -> ModeExpr {
    ModeExpr::Write {
        requires: Presence::Either,
    }
}

/// The same write, evaluated.
const fn write() -> Mode {
    Mode::Write {
        requires: Presence::Either,
    }
}

#[test]
fn a_routed_fresh_key_is_the_key_the_kernel_creates() {
    // The composer of this one-intent graph; nothing it calls is guarded.
    const COMPOSER: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
    let package = spawner();
    let package_hash = PackageHash(Hash32([1; 32]));
    let mut cache = MetadataCache::new();
    cache.publish(package_hash, package);
    let mut instances = InstanceRegistry::new();
    let creator = instances.create(
        &TestHasher,
        InstanceMeta {
            package: package_hash,
            config: vec![],
            salt: Hash32([1; 32]),
        },
    );

    // Two manifest nodes so the created object comes from a non-zero node
    // index — the namespacing the derivation must carry.
    let graph = ManifestGraph {
        nodes: vec![
            GraphNode {
                target: creator.into(),
                method: "spawn".into(),
                args: vec![],
                evidence: BTreeSet::new(),
            },
            GraphNode {
                target: creator.into(),
                method: "spawn".into(),
                args: vec![],
                evidence: BTreeSet::new(),
            },
        ],
    };
    let admitted = admit(&graph, COMPOSER, &cache, &instances, &TestHasher).expect("admits");
    let identity = admitted.identity();
    let routing = route(
        &admitted,
        &cache,
        &instances,
        &TestHasher,
        &PrefixShardResolver { bits: 8 },
    )
    .unwrap();
    // Asked of the resolver rather than restated: the claim is about the
    // creator's shard holding the key, not about what it is called.
    let declared = &routing.per_shard[&PrefixShardResolver { bits: 8 }.shard_of(creator.address())];

    // The kernel executes node 1: its creation context derives from the
    // same transaction identity, node index, and frame.
    let mut store = MemoryStore::new();
    let mut ctx = CreationContext::new(creator.address(), identity, 1, 0);
    let created = ctx.create(&mut store, &TestHasher, vec![42]).unwrap();
    assert!(declared.contains(&Effect {
        target: EffectTarget::Point(created),
        mode: write(),
    }));

    // The entry's fresh sequence agrees the same way.
    let seq = fresh_id(&TestHasher, identity, 1, 0, 1);
    store
        .entry_write(
            creator.address(),
            collection_id(&TestHasher, creator.address(), SlotId(4), &[]),
            (u128::from(99u64) << 64) | u128::from(seq),
            vec![7],
        )
        .unwrap();
    assert!(declared.contains(&Effect {
        target: EffectTarget::Entry {
            owner: creator.into(),
            collection: collection_id(&TestHasher, creator.address(), SlotId(4), &[]),
            order: (u128::from(99u64) << 64) | u128::from(seq),
        },
        mode: Mode::Write {
            requires: Presence::Either
        },
    }));

    // Node 0's creation is a different key: the node index namespaces.
    let mut other = CreationContext::new(creator.address(), identity, 0, 0);
    let from_node_zero = other.fresh_key(&TestHasher);
    assert_ne!(from_node_zero, created);
    assert!(declared.contains(&Effect {
        target: EffectTarget::Point(from_node_zero),
        mode: Mode::Write {
            requires: Presence::Either
        },
    }));
}
