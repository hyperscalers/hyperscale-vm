//! The three target shapes — transfer, AMM swap, order book — routed end to
//! end with their predicted effect profiles asserted exactly, plus the
//! over-approximation guarantee: a declared superset evaluates without
//! error.

mod common;

use std::collections::BTreeMap;

use common::{
    ALICE, ASKS, BASE, BOB, FILL_CAP, QUOTE, RES_X, RES_Y, admit_leaf, auth, book, config_leaf,
    declared_vault, effect_set, nullifier_write, pkg, pool, quarantine, refused, resolver, shapes,
    shard_of, vault, wide_account_metadata, world,
};
use hyperscale_hbor::Capped;
use hyperscale_vm_effects::{
    AdmissionError, ClaimRef, Composed, EdgeRef, GraphArg, GraphNode, Hash32, InstanceMeta,
    ManifestGraph, Records, ResolveError, TestHasher, Value, collection_id, fresh_id, per_shard,
};
use hyperscale_vm_types::{Address, Effect, EffectTarget, Mode, Moves};

/// One consumed output edge, unconstrained.
const fn edge(producer: u32, output: u32) -> GraphArg {
    GraphArg::edge(EdgeRef { producer, output }, vec![])
}

/// An ordinary write: on a leaf that may or may not be there.
const fn write() -> Mode {
    Mode::Write { moves: Moves::Both }
}

/// The instantiation fence's read of `owner`'s configuration leaf, which
/// every method of an instance-serving package carries.
fn fence_read(owner: impl Into<Address>) -> Effect {
    Effect {
        target: EffectTarget::Point(config_leaf(owner)),
        mode: Mode::Read,
    }
}

#[test]
fn transfer_reserves_at_the_sender_and_deltas_at_the_recipient() {
    let chain = world();
    let usdc = RES_X;
    let graph = ManifestGraph {
        nodes: Capped::new(vec![
            GraphNode {
                target: ALICE.into(),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(usdc.address())),
                    GraphArg::Literal(Value::U128(100)),
                ],
                evidence: Capped::from_members([ClaimRef::Account(ALICE)]),
            },
            GraphNode {
                target: BOB.into(),
                method: "deposit".into(),
                args: vec![edge(0, 0)],
                evidence: Capped::default(),
            },
        ])
        .unwrap(),
    };
    let admitted = admit_leaf(&graph, ALICE, &chain, &TestHasher).expect("admits");
    let routing = per_shard(&admitted, &resolver());

    let expected = BTreeMap::from([
        (
            shard_of(ALICE),
            effect_set(&[
                nullifier_write(ALICE, &graph),
                Effect {
                    target: EffectTarget::Point(auth(ALICE)),
                    mode: Mode::Read,
                },
                Effect {
                    target: EffectTarget::Point(vault(ALICE, usdc)),
                    mode: Mode::Reserve { amount: 100 },
                },
            ]),
        ),
        (
            shard_of(BOB),
            effect_set(&[
                Effect {
                    target: EffectTarget::Point(vault(BOB, usdc)),
                    mode: Mode::Delta { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(quarantine(BOB, usdc)),
                    mode: Mode::Delta { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(refused(BOB, usdc)),
                    mode: Mode::Read,
                },
            ]),
        ),
    ]);
    assert_eq!(shapes(&routing), shapes(&expected));
}

#[test]
fn swap_writes_both_reserves_and_reads_the_config() {
    let chain = world();
    let graph = ManifestGraph {
        nodes: Capped::new(vec![
            GraphNode {
                target: ALICE.into(),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X.address())),
                    GraphArg::Literal(Value::U128(500)),
                ],
                evidence: Capped::from_members([ClaimRef::Account(ALICE)]),
            },
            GraphNode {
                target: pool().into(),
                method: "swap".into(),
                args: vec![edge(0, 0), GraphArg::Literal(Value::U128(50))],
                evidence: Capped::default(),
            },
            GraphNode {
                target: ALICE.into(),
                method: "deposit".into(),
                args: vec![edge(1, 0)],
                evidence: Capped::default(),
            },
        ])
        .unwrap(),
    };
    let admitted = admit_leaf(&graph, ALICE, &chain, &TestHasher).expect("admits");
    let routing = per_shard(&admitted, &resolver());

    let expected = BTreeMap::from([
        (
            shard_of(ALICE),
            effect_set(&[
                nullifier_write(ALICE, &graph),
                Effect {
                    target: EffectTarget::Point(auth(ALICE)),
                    mode: Mode::Read,
                },
                Effect {
                    target: EffectTarget::Point(vault(ALICE, RES_X)),
                    mode: Mode::Reserve { amount: 500 },
                },
                Effect {
                    target: EffectTarget::Point(vault(ALICE, RES_Y)),
                    mode: Mode::Delta { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(quarantine(ALICE, RES_Y)),
                    mode: Mode::Delta { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(refused(ALICE, RES_Y)),
                    mode: Mode::Read,
                },
            ]),
        ),
        (
            shard_of(pool()),
            effect_set(&[
                fence_read(pool()),
                // The sold side only receives and the bought side only
                // pays out, each under its own balance read, so each
                // exclusive hold carries the one direction it kept.
                Effect {
                    target: EffectTarget::Point(declared_vault(pool(), 16, RES_X)),
                    mode: Mode::Write { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(declared_vault(pool(), 16, RES_Y)),
                    mode: Mode::Write { moves: Moves::Out },
                },
            ]),
        ),
    ]);
    assert_eq!(shapes(&routing), shapes(&expected));
}

#[test]
fn order_book_place_inserts_at_a_computed_entry() {
    let chain = world();
    let graph = ManifestGraph {
        nodes: Capped::new(vec![
            GraphNode {
                target: ALICE.into(),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(BASE.address())),
                    GraphArg::Literal(Value::U128(10)),
                ],
                evidence: Capped::from_members([ClaimRef::Account(ALICE)]),
            },
            GraphNode {
                target: book().into(),
                method: "place_ask".into(),
                args: vec![GraphArg::Literal(Value::U64(105)), edge(0, 0)],
                evidence: Capped::default(),
            },
        ])
        .unwrap(),
    };
    let admitted = admit_leaf(&graph, ALICE, &chain, &TestHasher).expect("admits");
    let routing = per_shard(&admitted, &resolver());

    let seq = fresh_id(&TestHasher, admitted.identity(), 1, 0);
    // Grouped rather than listed per shard, because which shard an
    // address lands on is a fact about the address and two of them
    // sharing one is not a case this test is about.
    let mut grouped: BTreeMap<_, Vec<Effect>> = BTreeMap::new();
    grouped.entry(shard_of(ALICE)).or_default().extend([
        nullifier_write(ALICE, &graph),
        Effect {
            target: EffectTarget::Point(auth(ALICE)),
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Point(vault(ALICE, BASE)),
            mode: Mode::Reserve { amount: 10 },
        },
    ]);
    grouped.entry(shard_of(book())).or_default().extend([
        fence_read(book()),
        Effect {
            target: EffectTarget::Entry {
                owner: book().into(),
                collection: collection_id(&TestHasher, book(), ASKS, &[]),
                order: (u128::from(105u64) << 64) | u128::from(seq),
            },
            mode: write(),
        },
        Effect {
            target: EffectTarget::Point(declared_vault(book(), 16, BASE)),
            mode: Mode::Delta { moves: Moves::In },
        },
    ]);
    let expected: BTreeMap<_, _> = grouped
        .into_iter()
        .map(|(shard, effects)| (shard, effect_set(&effects)))
        .collect();
    assert_eq!(shapes(&routing), shapes(&expected));
}

#[test]
#[allow(clippy::too_many_lines)] // one entry per cell each side of the fill provisions
fn order_book_fill_declares_a_capped_price_interval() {
    let chain = world();
    let graph = ManifestGraph {
        nodes: Capped::new(vec![
            GraphNode {
                target: BOB.into(),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(QUOTE.address())),
                    GraphArg::Literal(Value::U128(1000)),
                ],
                evidence: Capped::from_members([ClaimRef::Account(BOB)]),
            },
            GraphNode {
                target: book().into(),
                method: "fill_asks".into(),
                args: vec![
                    GraphArg::Literal(Value::U64(100)),
                    GraphArg::Literal(Value::U64(110)),
                    edge(0, 0),
                ],
                evidence: Capped::default(),
            },
            // The fill returns what it bought and what it did not spend;
            // both edges have to land somewhere.
            GraphNode {
                target: BOB.into(),
                method: "deposit".into(),
                args: vec![edge(1, 0)],
                evidence: Capped::default(),
            },
            GraphNode {
                target: BOB.into(),
                method: "deposit".into(),
                args: vec![edge(1, 1)],
                evidence: Capped::default(),
            },
        ])
        .unwrap(),
    };
    let admitted = admit_leaf(&graph, BOB, &chain, &TestHasher).expect("admits");
    let routing = per_shard(&admitted, &resolver());

    let expected = BTreeMap::from([
        (
            shard_of(BOB),
            effect_set(&[
                nullifier_write(BOB, &graph),
                Effect {
                    target: EffectTarget::Point(auth(BOB)),
                    mode: Mode::Read,
                },
                Effect {
                    target: EffectTarget::Point(vault(BOB, QUOTE)),
                    mode: Mode::Reserve { amount: 1000 },
                },
                Effect {
                    target: EffectTarget::Point(vault(BOB, BASE)),
                    mode: Mode::Delta { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(quarantine(BOB, BASE)),
                    mode: Mode::Delta { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(refused(BOB, BASE)),
                    mode: Mode::Read,
                },
                // The unspent quote comes back to the same vault the
                // reservation was taken from.
                Effect {
                    target: EffectTarget::Point(vault(BOB, QUOTE)),
                    mode: Mode::Delta { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(quarantine(BOB, QUOTE)),
                    mode: Mode::Delta { moves: Moves::In },
                },
                Effect {
                    target: EffectTarget::Point(refused(BOB, QUOTE)),
                    mode: Mode::Read,
                },
            ]),
        ),
        (
            shard_of(book()),
            effect_set(&[
                fence_read(book()),
                Effect {
                    target: EffectTarget::Range {
                        owner: book().into(),
                        collection: collection_id(&TestHasher, book(), ASKS, &[]),
                        lo: u128::from(100u64) << 64,
                        hi: (u128::from(110u64) << 64) | u128::from(u64::MAX),
                        cap: FILL_CAP,
                    },
                    mode: write(),
                },
                // The base only leaves the book's own vault and the
                // payment only arrives, so each side is judged on the
                // one movement it makes.
                Effect {
                    target: EffectTarget::Point(declared_vault(book(), 16, BASE)),
                    mode: Mode::Delta { moves: Moves::Out },
                },
                Effect {
                    target: EffectTarget::Point(declared_vault(book(), 17, QUOTE)),
                    mode: Mode::Delta { moves: Moves::In },
                },
            ]),
        ),
    ]);
    assert_eq!(shapes(&routing), shapes(&expected));
}

#[test]
fn a_declared_superset_evaluates_without_error() {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(pkg("wide"), wide_account_metadata());
    let alice = chain.instances.create(
        &TestHasher,
        InstanceMeta {
            package: pkg("wide"),
            config: Capped::empty(),
            salt: Hash32([1; 32]),
        },
    );
    let graph = ManifestGraph {
        nodes: Capped::new(vec![
            GraphNode {
                target: alice.into(),
                method: "withdraw_wide".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X.address())),
                    GraphArg::Literal(Value::U128(1)),
                ],
                evidence: Capped::default(),
            },
            GraphNode {
                target: alice.into(),
                method: "deposit".into(),
                args: vec![edge(0, 0)],
                evidence: Capped::default(),
            },
        ])
        .unwrap(),
    };
    let admitted = admit_leaf(&graph, ALICE, &chain, &TestHasher).expect("admits");
    let routing = per_shard(&admitted, &resolver());
    let set = &routing[&shard_of(alice)];
    // The exact effect and the never-touched superset both routed; three
    // more are the deposit that consumes the withdrawal — where it may
    // land, where else it may land, and the flag that picks — and the
    // last is the fence's read of the target's own configuration leaf.
    assert!(set.contains(&Effect {
        target: EffectTarget::Point(vault(alice, RES_X)),
        mode: Mode::Reserve { amount: 1 },
    }));
    assert!(set.contains(&fence_read(alice)));
    assert_eq!(set.len(), 6);
}

/// A presented instance record is the whole of instantiation: the swap
/// that resolves against a registry holding the pool resolves
/// identically against a bare registry composed with the pool's record —
/// and against nothing else.
#[test]
fn a_presented_record_is_the_whole_of_instantiation() {
    let registered = world();
    let bare = common::bare_world();

    let graph = ManifestGraph {
        nodes: Capped::new(vec![
            GraphNode {
                target: ALICE.into(),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X.address())),
                    GraphArg::Literal(Value::U128(500)),
                ],
                evidence: Capped::from_members([ClaimRef::Account(ALICE)]),
            },
            GraphNode {
                target: pool().into(),
                method: "swap".into(),
                args: vec![edge(0, 0), GraphArg::Literal(Value::U128(50))],
                evidence: Capped::default(),
            },
            GraphNode {
                target: ALICE.into(),
                method: "deposit".into(),
                args: vec![edge(1, 0)],
                evidence: Capped::default(),
            },
        ])
        .unwrap(),
    };

    // Unregistered and uncertified: the target is unresolvable.
    assert!(matches!(
        admit_leaf(&graph, ALICE, &bare, &TestHasher),
        Err(AdmissionError::Resolve(ResolveError::UnknownInstance(_)))
    ));

    // A record for some other instance enables nothing at the pool.
    let elsewhere = Composed::new(&bare, &[common::book_meta()], &TestHasher);
    assert!(matches!(
        admit_leaf(&graph, ALICE, &elsewhere, &TestHasher),
        Err(AdmissionError::Resolve(ResolveError::UnknownInstance(_)))
    ));

    // The pool's own record resolves the call — to exactly the
    // routing a pre-registered world derives.
    let certified = Composed::new(&bare, &[common::pool_meta()], &TestHasher);
    let admitted = admit_leaf(&graph, ALICE, &certified, &TestHasher).expect("admits");
    let routing = per_shard(&admitted, &resolver());

    let reference = admit_leaf(&graph, ALICE, &registered, &TestHasher).expect("admits");
    let reference = per_shard(&reference, &resolver());
    assert_eq!(routing, reference);
}
