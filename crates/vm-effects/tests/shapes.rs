//! The three target shapes — transfer, AMM swap, order book — routed end to
//! end with their predicted effect profiles asserted exactly, plus the
//! over-approximation guarantee: a declared superset evaluates without
//! error.

mod common;

use std::collections::BTreeMap;

use common::{
    ALICE, ASKS, BASE, BOB, BOOK, FILL_CAP, POOL, QUOTE, RES_X, RES_Y, claims, config_leaf,
    effect_set, identity, pkg, resolver, shard_of, vault, wide_account_metadata, world,
};
use hyperscale_vm_effects::{
    Effect, EffectTarget, InstanceMeta, InstanceRegistry, Manifest, MetadataCache, Mode, Node,
    NodeInput, TestHasher, Value, Window, fresh_id, route,
};

#[test]
fn transfer_reserves_at_the_sender_and_deltas_at_the_recipient() {
    let (cache, instances) = world();
    let usdc = RES_X;
    let manifest = Manifest {
        nodes: vec![
            Node {
                target: ALICE,
                method: "withdraw".into(),
                inputs: vec![
                    NodeInput::Literal(Value::Address(usdc)),
                    NodeInput::Literal(Value::U128(100)),
                ],
            },
            Node {
                target: BOB,
                method: "deposit".into(),
                inputs: vec![NodeInput::Edge {
                    source: 0,
                    resource: usdc,
                }],
            },
        ],
    };
    let routing = route(
        &manifest,
        identity(),
        &cache,
        &instances,
        &TestHasher,
        &resolver(),
    )
    .unwrap();

    let expected = BTreeMap::from([
        (
            shard_of(ALICE),
            effect_set(&[Effect {
                target: EffectTarget::Point(vault(ALICE, usdc)),
                mode: Mode::Reserve { amount: 100 },
            }]),
        ),
        (
            shard_of(BOB),
            effect_set(&[
                Effect {
                    target: EffectTarget::Point(vault(BOB, usdc)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: EffectTarget::Point(claims(BOB, usdc)),
                    mode: Mode::Delta,
                },
            ]),
        ),
    ]);
    assert_eq!(routing.per_shard, expected);
    assert!(routing.snapshot_obligations.is_empty());
    assert!(routing.call_graph.edges.is_empty());
}

#[test]
fn swap_writes_both_reserves_and_snapshots_locked_config() {
    let (cache, instances) = world();
    let manifest = Manifest {
        nodes: vec![
            Node {
                target: ALICE,
                method: "withdraw".into(),
                inputs: vec![
                    NodeInput::Literal(Value::Address(RES_X)),
                    NodeInput::Literal(Value::U128(500)),
                ],
            },
            Node {
                target: POOL,
                method: "swap".into(),
                inputs: vec![
                    NodeInput::Edge {
                        source: 0,
                        resource: RES_X,
                    },
                    NodeInput::Literal(Value::U128(50)),
                ],
            },
            Node {
                target: ALICE,
                method: "deposit".into(),
                inputs: vec![NodeInput::Edge {
                    source: 1,
                    resource: RES_Y,
                }],
            },
        ],
    };
    let routing = route(
        &manifest,
        identity(),
        &cache,
        &instances,
        &TestHasher,
        &resolver(),
    )
    .unwrap();

    let expected = BTreeMap::from([
        (
            shard_of(ALICE),
            effect_set(&[
                Effect {
                    target: EffectTarget::Point(vault(ALICE, RES_X)),
                    mode: Mode::Reserve { amount: 500 },
                },
                Effect {
                    target: EffectTarget::Point(vault(ALICE, RES_Y)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: EffectTarget::Point(claims(ALICE, RES_Y)),
                    mode: Mode::Delta,
                },
            ]),
        ),
        (
            shard_of(POOL),
            effect_set(&[
                Effect {
                    target: EffectTarget::Point(config_leaf(POOL)),
                    mode: Mode::Snapshot {
                        window: Window::Unbounded,
                    },
                },
                Effect {
                    target: EffectTarget::Point(vault(POOL, RES_X)),
                    mode: Mode::Write,
                },
                Effect {
                    target: EffectTarget::Point(vault(POOL, RES_Y)),
                    mode: Mode::Write,
                },
            ]),
        ),
    ]);
    assert_eq!(routing.per_shard, expected);
    // The locked-config snapshot is unbounded: no proof obligation.
    assert!(routing.snapshot_obligations.is_empty());
}

#[test]
fn order_book_place_inserts_at_a_computed_entry() {
    let (cache, instances) = world();
    let manifest = Manifest {
        nodes: vec![
            Node {
                target: ALICE,
                method: "withdraw".into(),
                inputs: vec![
                    NodeInput::Literal(Value::Address(BASE)),
                    NodeInput::Literal(Value::U128(10)),
                ],
            },
            Node {
                target: BOOK,
                method: "place_ask".into(),
                inputs: vec![
                    NodeInput::Literal(Value::U64(105)),
                    NodeInput::Edge {
                        source: 0,
                        resource: BASE,
                    },
                ],
            },
        ],
    };
    let routing = route(
        &manifest,
        identity(),
        &cache,
        &instances,
        &TestHasher,
        &resolver(),
    )
    .unwrap();

    let seq = fresh_id(&TestHasher, identity(), 1, 0, 0);
    let expected = BTreeMap::from([
        (
            shard_of(ALICE),
            effect_set(&[Effect {
                target: EffectTarget::Point(vault(ALICE, BASE)),
                mode: Mode::Reserve { amount: 10 },
            }]),
        ),
        (
            shard_of(BOOK),
            effect_set(&[
                Effect {
                    target: EffectTarget::Entry {
                        owner: BOOK,
                        collection: ASKS,
                        order: (u128::from(105u64) << 64) | u128::from(seq),
                    },
                    mode: Mode::Write,
                },
                Effect {
                    target: EffectTarget::Point(vault(BOOK, BASE)),
                    mode: Mode::Delta,
                },
            ]),
        ),
    ]);
    assert_eq!(routing.per_shard, expected);
}

#[test]
fn order_book_fill_declares_a_capped_price_interval() {
    let (cache, instances) = world();
    let manifest = Manifest {
        nodes: vec![
            Node {
                target: BOB,
                method: "withdraw".into(),
                inputs: vec![
                    NodeInput::Literal(Value::Address(QUOTE)),
                    NodeInput::Literal(Value::U128(1000)),
                ],
            },
            Node {
                target: BOOK,
                method: "fill_asks".into(),
                inputs: vec![
                    NodeInput::Literal(Value::U64(100)),
                    NodeInput::Literal(Value::U64(110)),
                    NodeInput::Edge {
                        source: 0,
                        resource: QUOTE,
                    },
                ],
            },
            Node {
                target: BOB,
                method: "deposit".into(),
                inputs: vec![NodeInput::Edge {
                    source: 1,
                    resource: BASE,
                }],
            },
        ],
    };
    let routing = route(
        &manifest,
        identity(),
        &cache,
        &instances,
        &TestHasher,
        &resolver(),
    )
    .unwrap();

    let expected = BTreeMap::from([
        (
            shard_of(BOB),
            effect_set(&[
                Effect {
                    target: EffectTarget::Point(vault(BOB, QUOTE)),
                    mode: Mode::Reserve { amount: 1000 },
                },
                Effect {
                    target: EffectTarget::Point(vault(BOB, BASE)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: EffectTarget::Point(claims(BOB, BASE)),
                    mode: Mode::Delta,
                },
            ]),
        ),
        (
            shard_of(BOOK),
            effect_set(&[
                Effect {
                    target: EffectTarget::Range {
                        owner: BOOK,
                        collection: ASKS,
                        lo: u128::from(100u64) << 64,
                        hi: (u128::from(110u64) << 64) | u128::from(u64::MAX),
                        cap: FILL_CAP,
                    },
                    mode: Mode::Write,
                },
                Effect {
                    target: EffectTarget::Point(vault(BOOK, BASE)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: EffectTarget::Point(vault(BOOK, QUOTE)),
                    mode: Mode::Delta,
                },
            ]),
        ),
    ]);
    assert_eq!(routing.per_shard, expected);
}

#[test]
fn a_declared_superset_evaluates_without_error() {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("wide"), wide_account_metadata());
    let mut instances = InstanceRegistry::new();
    instances.register(
        ALICE,
        InstanceMeta {
            package: pkg("wide"),
            config: vec![],
        },
    );
    let manifest = Manifest {
        nodes: vec![Node {
            target: ALICE,
            method: "withdraw_wide".into(),
            inputs: vec![
                NodeInput::Literal(Value::Address(RES_X)),
                NodeInput::Literal(Value::U128(1)),
            ],
        }],
    };
    let routing = route(
        &manifest,
        identity(),
        &cache,
        &instances,
        &TestHasher,
        &resolver(),
    )
    .unwrap();
    let set = &routing.per_shard[&shard_of(ALICE)];
    // The exact effect and the never-touched superset both routed.
    assert!(set.contains(&Effect {
        target: EffectTarget::Point(vault(ALICE, RES_X)),
        mode: Mode::Reserve { amount: 1 },
    }));
    assert_eq!(set.len(), 2);
}
