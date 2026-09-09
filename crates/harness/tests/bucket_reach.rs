//! One transaction, two nodes, two packages: what the second one can
//! reach of the value the first one left in flight.
//!
//! [`node_reach`] states the site axis of reach — a body names any
//! capability the transaction declared. This lane states the bucket
//! axis. The bucket table is one flat slot vector for the transaction,
//! a rep is the position a take or split minted, and an edge a producer
//! returned stays in the table until the node it was routed to consumes
//! it. Between those two nodes it is a number, and a body that writes
//! the number holds it: a prowler names the keeper's in-flight edge,
//! merges it into a bucket of its own with `bucket-put`, and credits
//! its own vault with the total.
//!
//! What the composition then does with the transaction depends on node
//! order, and the lane records each way. With no consumer declared, the
//! transaction settles: the keeper's vault is debited and the prowler's
//! credited, and the close finds no value in flight because the slot
//! the prowler drained is empty. With the edge's consumer declared after
//! the prowler, the walk finds the slot empty where it judges the
//! consumer's signed bound and refuses the batch as a composition
//! defect — priced to nobody, though a guest caused it. With the
//! consumer ahead of the prowler, the edge is gone before the prowler
//! names it, and what refuses is the table: an unknown handle.
//!
//! The number is knowable. Reps are minted from zero in the order the
//! transaction opens buckets, so the first take of the first node is
//! rep 0 whatever else the manifest declares, and whoever composed the
//! manifest knows which node runs first.

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

/// The prowler merges the keeper's in-flight edge into its own bucket,
/// and the transaction settles with the value in the prowler's vault.
///
/// The keeper's node was lent its vault and produced an edge; the
/// prowler's node was lent its own vault and nothing else. What the
/// prowler needed in order to take the keeper's value was the number,
/// and the close balances because the slot it drained is empty.
#[test]
fn a_node_merges_a_bucket_an_earlier_node_left_in_flight() {
    let fx = fixture();
    let (outcome, end) = walked(&fx, vec![taking(&fx), stealing(&fx)]);

    assert!(
        matches!(outcome, Outcome::Completed { .. }),
        "the theft settled: {outcome:?}"
    );
    assert_eq!(
        amount_of(&end, fx.kept),
        BALANCE - TAKEN,
        "the keeper's vault paid the edge"
    );
    assert_eq!(
        amount_of(&end, fx.prowled),
        BALANCE + TAKEN,
        "and the prowler's vault received it"
    );
}

/// With the edge's consumer declared after the prowler, the walk finds
/// the slot empty where it judges the consumer's signed bound, and
/// refuses the batch as a composition defect.
///
/// The verdict is priced to nobody: the walk reads an empty producer
/// slot as the plan naming an edge nothing produced, which is a defect
/// in whoever composed the batch — though here a guest emptied it.
#[test]
fn a_consumer_declared_after_the_prowler_finds_the_edge_gone() {
    let fx = fixture();
    let (outcome, end) = walked(&fx, vec![taking(&fx), stealing(&fx), receiving(&fx)]);

    assert_eq!(
        outcome,
        Outcome::ProtocolError {
            reason: AbortReason::MissingProducerEdge
        }
    );
    assert_eq!(amount_of(&end, fx.kept), BALANCE, "nothing committed");
    assert_eq!(amount_of(&end, fx.prowled), BALANCE);
}

/// With the consumer ahead of the prowler, the edge is consumed before
/// the prowler names it, and the table refuses the rep as unknown.
///
/// Node order is the composer's, so whether the reach spends anything
/// is decided by where the composer put the consumer rather than by
/// anything the kernel judges.
#[test]
fn a_consumer_declared_ahead_of_the_prowler_leaves_it_nothing_to_name() {
    let fx = fixture();
    let (outcome, end) = walked(&fx, vec![taking(&fx), receiving(&fx), stealing(&fx)]);

    assert_eq!(
        outcome,
        Outcome::UserError {
            reason: AbortReason::HandleUnknown
        }
    );
    assert_eq!(amount_of(&end, fx.kept), BALANCE, "nothing committed");
    assert_eq!(amount_of(&end, fx.prowled), BALANCE);
}
