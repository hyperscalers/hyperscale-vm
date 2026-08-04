//! The three target shapes — transfer, AMM swap, order book — routed end to
//! end with their predicted effect profiles asserted exactly, plus the
//! over-approximation guarantee: a declared superset evaluates without
//! error.

mod common;

use std::collections::BTreeMap;

use common::{
    ALICE, ASKS, BASE, BOB, BOOK, FILL_CAP, POOL, QUOTE, RES_X, RES_Y, claims, config_leaf,
    effect_set, pkg, resolver, shard_of, vault, wide_account_metadata, world,
};
use hyperscale_vm_effects::{
    EdgeRef, Effect, EffectTarget, GraphArg, GraphNode, InstanceMeta, InstanceRegistry,
    ManifestGraph, MetadataCache, Mode, TestHasher, Value, admit, fresh_id, route,
};

/// One consumed output edge, unconstrained.
const fn edge(producer: u32, output: u32) -> GraphArg {
    GraphArg::Edge {
        edge: EdgeRef { producer, output },
        constraints: vec![],
    }
}

#[test]
fn transfer_reserves_at_the_sender_and_deltas_at_the_recipient() {
    let (cache, instances) = world();
    let usdc = RES_X;
    let graph = ManifestGraph {
        nodes: vec![
            GraphNode {
                target: ALICE,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(usdc)),
                    GraphArg::Literal(Value::U128(100)),
                ],
            },
            GraphNode {
                target: BOB,
                method: "deposit".into(),
                args: vec![edge(0, 0)],
            },
        ],
    };
    let admitted = admit(&graph, &cache, &instances, &TestHasher).expect("admits");
    let routing = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();

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
    assert!(routing.call_graph.edges.is_empty());
}

#[test]
fn swap_writes_both_reserves_and_reads_the_locked_config() {
    let (cache, instances) = world();
    let graph = ManifestGraph {
        nodes: vec![
            GraphNode {
                target: ALICE,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X)),
                    GraphArg::Literal(Value::U128(500)),
                ],
            },
            GraphNode {
                target: POOL,
                method: "swap".into(),
                args: vec![edge(0, 0), GraphArg::Literal(Value::U128(50))],
            },
            GraphNode {
                target: ALICE,
                method: "deposit".into(),
                args: vec![edge(1, 0)],
            },
        ],
    };
    let admitted = admit(&graph, &cache, &instances, &TestHasher).expect("admits");
    let routing = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();

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
                    mode: Mode::Locked,
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
}

#[test]
fn order_book_place_inserts_at_a_computed_entry() {
    let (cache, instances) = world();
    let graph = ManifestGraph {
        nodes: vec![
            GraphNode {
                target: ALICE,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(BASE)),
                    GraphArg::Literal(Value::U128(10)),
                ],
            },
            GraphNode {
                target: BOOK,
                method: "place_ask".into(),
                args: vec![GraphArg::Literal(Value::U64(105)), edge(0, 0)],
            },
        ],
    };
    let admitted = admit(&graph, &cache, &instances, &TestHasher).expect("admits");
    let routing = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();

    let seq = fresh_id(&TestHasher, admitted.identity(), 1, 0, 0);
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
    let graph = ManifestGraph {
        nodes: vec![
            GraphNode {
                target: BOB,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(QUOTE)),
                    GraphArg::Literal(Value::U128(1000)),
                ],
            },
            GraphNode {
                target: BOOK,
                method: "fill_asks".into(),
                args: vec![
                    GraphArg::Literal(Value::U64(100)),
                    GraphArg::Literal(Value::U64(110)),
                    edge(0, 0),
                ],
            },
            // The fill returns what it bought and what it did not spend;
            // both edges have to land somewhere.
            GraphNode {
                target: BOB,
                method: "deposit".into(),
                args: vec![edge(1, 0)],
            },
            GraphNode {
                target: BOB,
                method: "deposit".into(),
                args: vec![edge(1, 1)],
            },
        ],
    };
    let admitted = admit(&graph, &cache, &instances, &TestHasher).expect("admits");
    let routing = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();

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
                // The unspent quote comes back to the same vault the
                // reservation was taken from.
                Effect {
                    target: EffectTarget::Point(vault(BOB, QUOTE)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: EffectTarget::Point(claims(BOB, QUOTE)),
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
    let graph = ManifestGraph {
        nodes: vec![
            GraphNode {
                target: ALICE,
                method: "withdraw_wide".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X)),
                    GraphArg::Literal(Value::U128(1)),
                ],
            },
            GraphNode {
                target: ALICE,
                method: "deposit".into(),
                args: vec![edge(0, 0)],
            },
        ],
    };
    let admitted = admit(&graph, &cache, &instances, &TestHasher).expect("admits");
    let routing = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();
    let set = &routing.per_shard[&shard_of(ALICE)];
    // The exact effect and the never-touched superset both routed; the
    // remaining two are the deposit that consumes the withdrawal.
    assert!(set.contains(&Effect {
        target: EffectTarget::Point(vault(ALICE, RES_X)),
        mode: Mode::Reserve { amount: 1 },
    }));
    assert_eq!(set.len(), 4);
}
