//! One transaction, two nodes, two packages: what the second one can
//! reach of the value the first one left in flight.
//!
//! `node_reach.rs` states the site axis of reach; this lane states the
//! bucket axis. The bucket table is one flat slot vector for the
//! transaction, a rep is the position a take or split minted, and an
//! edge a producer returned stays in the table until the node it was
//! routed to consumes it. Between those two nodes it is a number, and
//! reps are minted from zero in the order the transaction opens
//! buckets, so the first take of the first node is rep 0 whatever else
//! the manifest declares — a number whoever composed the manifest
//! knows.
//!
//! What a frame can do with the number is nothing. A frame resolves the
//! buckets the walk lent it and the ones it opened itself, and an edge
//! in flight between two other nodes is neither, so a prowler that
//! names it to merge it into a bucket of its own is refused as outside
//! its frame. The refusal is the same wherever the composer put the
//! edge's consumer — after the prowler, ahead of it, or nowhere — so
//! node order decides nothing about what a frame can reach. The node
//! the edge was routed to reaches it, which is the positive case.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Bounds, CallArg, Declaration, EdgeBound, EdgeContent, Hash32, Hasher, NodeCall, PackageHash,
    TestHasher,
};
use hyperscale_vm_embed::abi::{ABI, MEMORY, STATE};
use hyperscale_vm_harness::driver::{Lanes, amount_of, run_lanes, seed_vault, test_hash, vault};
use hyperscale_vm_harness::dual::rep_where;
use hyperscale_vm_kernel::{
    BatchTx, Capability, EnvInputs, KernelSession, MemoryStore, OverlayStore,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Moves, Outcome,
    ResourceAddr, SubstateKey, TxHash,
};
use wat::parse_str;

/// What both vaults hold.
const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

/// The keeper's instance, and the owner of the vault its node is lent.
const KEEPER: Address = Address::new([0xA1; 31], AddressClass::Component);

/// The prowler's instance, and the owner of the vault its node is lent.
const PROWLER: Address = Address::new([0xB1; 31], AddressClass::Component);

/// What each vault holds before the transaction.
const BALANCE: u128 = 100;

/// What the keeper takes into the edge it leaves in flight.
const TAKEN: u128 = 70;

/// What the prowler takes from its own vault, so that it holds a bucket
/// of its own to merge the keeper's into.
const OWN: u128 = 5;

/// The rep of the keeper's edge: the first bucket the transaction
/// opens.
const FIRST_BUCKET: u32 = 0;

const fn tx() -> TxHash {
    TxHash(Hash32([0x3F; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(13_000)
}

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

/// Two vaults under one transaction, one declared for each node, both
/// lent for taking and putting.
struct Fixture {
    declared: EffectSet,
    store: MemoryStore,
    kept: SubstateKey,
    prowled: SubstateKey,
}

fn fixture() -> Fixture {
    let (kept, prowled) = (vault(KEEPER, RESOURCE), vault(PROWLER, RESOURCE));
    let mut store = MemoryStore::new();
    seed_vault(&mut store, KEEPER, RESOURCE, BALANCE);
    seed_vault(&mut store, PROWLER, RESOURCE, BALANCE);

    let mut declared = EffectSet::new();
    for key in [kept, prowled] {
        declared
            .insert(Effect {
                target: EffectTarget::Point(key),
                mode: Mode::Delta { moves: Moves::Both },
            })
            .expect("the set takes it");
    }

    Fixture {
        declared,
        store,
        kept,
        prowled,
    }
}

fn declaration(fx: &Fixture) -> Declaration {
    Declaration::from_set(fx.declared.clone()).denominated(|_| Some(RESOURCE))
}

/// A session over the fixture, for reading the table's layout.
fn probe(fx: &Fixture) -> KernelSession {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(fx.store.clone())),
        &declaration(fx),
        tx(),
        env(),
        test_hash,
    )
    .expect("the declaration materializes")
}

/// The rep of the capability over `wanted`.
fn rep_of(session: &KernelSession, wanted: SubstateKey) -> u32 {
    rep_where(
        session,
        |capability| matches!(capability, Capability::Delta { key, .. } if *key == wanted),
    )
}

/// The keeper: takes from the vault it was lent and hands the value on
/// as its one edge, or credits the vault with the edge it was handed.
fn keeper() -> Vec<u8> {
    let text = format!(
        r#"
(module
  (import "{STATE}" "site-take" (func $site_take (param i32 i32 i32) (result i32)))
  (import "{STATE}" "site-put" (func $site_put (param i32 i32 i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)

  ;; The amount at 0 is sixteen little-endian bytes; the high half is
  ;; memory's own zero.
  (func (export "take") (param $vault i32)
    (i64.store (i32.const 0) (i64.const {TAKEN}))
    (i32.store (i32.const 256)
      (call $site_take (local.get $vault) (i32.const 0) (i32.const 0)))
    (call $reply (i32.const 256) (i32.const 1)))

  (func (export "receive") (param $vault i32) (param $funds i32)
    (call $site_put (local.get $vault) (i32.const 0) (local.get $funds))
    (call $reply (i32.const 0) (i32.const 0))))
"#
    );
    parse_str(&text).expect("the keeper parses")
}

/// The prowler: takes a little from its own vault, merges the bucket at
/// `foreign` into it, and credits its vault with the total.
///
/// The number is in its text, which is where a body that knows the
/// manifest's shape would put it.
fn prowler(foreign: u32) -> Vec<u8> {
    let text = format!(
        r#"
(module
  (import "{STATE}" "site-take" (func $site_take (param i32 i32 i32) (result i32)))
  (import "{STATE}" "site-put" (func $site_put (param i32 i32 i32)))
  (import "{STATE}" "bucket-put" (func $bucket_put (param i32 i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)

  (func (export "steal") (param $vault i32)
    (local $own i32)
    (i64.store (i32.const 0) (i64.const {OWN}))
    (local.set $own
      (call $site_take (local.get $vault) (i32.const 0) (i32.const 0)))
    (call $bucket_put (local.get $own) (i32.const {foreign}))
    (call $site_put (local.get $vault) (i32.const 0) (local.get $own))
    (call $reply (i32.const 0) (i32.const 0))))
"#
    );
    parse_str(&text).expect("the prowler parses")
}

/// One node's lowered call, lent the one site over `site` and nothing
/// else.
fn node(package: PackageHash, target: Address, export: &str, site: u32) -> NodeCall {
    NodeCall {
        package,
        target,
        export: export.to_owned(),
        args: vec![CallArg::Site {
            entries: vec![Some(site)],
        }],
        edges: Vec::new(),
        outputs: Vec::new(),
        answers: false,
        issues: Vec::new(),
        evidence: Vec::new(),
        signed_in: None,
        requires: Vec::new(),
    }
}

/// The keeper's take: lent its vault, producing one fungible edge.
fn taking(fx: &Fixture) -> NodeCall {
    let mut call = node(pkg("keeper"), KEEPER, "take", rep_of(&probe(fx), fx.kept));
    call.outputs = vec![EdgeContent::Fungible];
    call
}

/// The keeper's receive: lent its vault and the edge node 0 produced,
/// under the bound a signer would write for it.
fn receiving(fx: &Fixture) -> NodeCall {
    let mut call = node(
        pkg("keeper"),
        KEEPER,
        "receive",
        rep_of(&probe(fx), fx.kept),
    );
    call.args.push(CallArg::Bucket {
        source: 0,
        output: 0,
    });
    call.edges = vec![EdgeBound {
        source: 0,
        output: 0,
        param: 1,
        bounds: Bounds {
            min: Some(TAKEN),
            max: None,
        },
    }];
    call
}

/// The prowler's steal: lent its own vault only.
fn stealing(fx: &Fixture) -> NodeCall {
    node(
        pkg("prowler"),
        PROWLER,
        "steal",
        rep_of(&probe(fx), fx.prowled),
    )
}

/// Both engines, each seeded with the two packages this lane composes.
fn lanes() -> Lanes {
    let mut lanes = Lanes::new();
    lanes.seed(pkg("keeper"), &keeper());
    lanes.seed(pkg("prowler"), &prowler(FIRST_BUCKET));
    lanes
}

/// Walk `calls` as one transaction on both engines, answering its
/// outcome and the end state.
fn walked(fx: &Fixture, calls: Vec<NodeCall>) -> (Outcome, MemoryStore) {
    let entry = BatchTx::new(tx(), declaration(fx), env()).with_calls(calls);
    let (outcome, end) = run_lanes(&lanes(), &fx.store, std::slice::from_ref(&entry));
    let receipt = outcome
        .receipts
        .get(&entry.tx)
        .expect("the batch receipts the entry");
    (receipt.outcome.clone(), end)
}

/// The prowler is refused, and nothing it did commits.
fn refused_outside_the_frame(fx: &Fixture, calls: Vec<NodeCall>) {
    let (outcome, end) = walked(fx, calls);
    assert_eq!(
        outcome,
        Outcome::UserError {
            reason: AbortReason::HandleOutsideFrame
        }
    );
    assert_eq!(amount_of(&end, fx.kept), BALANCE, "nothing committed");
    assert_eq!(amount_of(&end, fx.prowled), BALANCE);
}

/// The node an edge was routed to reaches it: the keeper takes, and the
/// keeper's receiving node credits the vault with the edge it was lent.
#[test]
fn the_node_an_edge_was_routed_to_reaches_it() {
    let fx = fixture();
    let (outcome, end) = walked(&fx, vec![taking(&fx), receiving(&fx)]);

    assert!(
        matches!(outcome, Outcome::Completed { .. }),
        "the edge came back: {outcome:?}"
    );
    assert_eq!(amount_of(&end, fx.kept), BALANCE, "taken and put back");
    assert_eq!(amount_of(&end, fx.prowled), BALANCE);
}

/// The prowler names the keeper's in-flight edge to merge it into its
/// own bucket, and its frame refuses the number.
///
/// The keeper's node was lent its vault and produced an edge; the
/// prowler's node was lent its own vault and nothing else, and the
/// bucket it opened for itself is the only one its frame resolves.
#[test]
fn a_node_cannot_merge_a_bucket_an_earlier_node_left_in_flight() {
    let fx = fixture();
    refused_outside_the_frame(&fx, vec![taking(&fx), stealing(&fx)]);
}

/// With the edge's consumer declared after the prowler, the refusal is
/// the same: the walk never reaches the consumer.
#[test]
fn a_consumer_declared_after_the_prowler_changes_nothing() {
    let fx = fixture();
    refused_outside_the_frame(&fx, vec![taking(&fx), stealing(&fx), receiving(&fx)]);
}

/// With the consumer ahead of the prowler, the edge is already consumed
/// when the prowler names it — and the fence still answers before the
/// table does, because the rep was never the prowler's to resolve.
#[test]
fn a_consumer_declared_ahead_of_the_prowler_changes_nothing() {
    let fx = fixture();
    refused_outside_the_frame(&fx, vec![taking(&fx), receiving(&fx), stealing(&fx)]);
}
