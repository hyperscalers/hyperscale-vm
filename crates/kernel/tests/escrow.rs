//! The value crossing: an execution that runs a subset of a manifest
//! issues what leaves it and claims what arrives, and each half balances
//! where it runs.
//!
//! The two halves are driven separately here, which is the point — they
//! are two shards, and nothing lets one read the other's session. What
//! reconciles them is the record cell and the attested amount, so those
//! are what these tests compare.

use std::sync::Arc;

use hyperscale_hbor::from_slice;
use hyperscale_vm_effects::{
    CallArg, ClaimCell, CrossingCell, CrossingSite, Declaration, EdgeContent, Hash32, Hasher,
    NodeCall, PackageHash, SlotId, SubintentHash, TestHasher, child_key,
};
use hyperscale_vm_embed::GuestArg;
use hyperscale_vm_kernel::{
    Baseline, BatchTx, Capability, Crossed, EnvInputs, ExecutionMode, GuestBackend, GuestCall,
    InvokeResult, Invoked, KernelSession, LegPlan, Locality, ManifestWalk, MemoryStore, Receipt,
    execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Effect, EffectSet, EffectTarget, MAX_CROSSINGS_PER_TX,
    Mode, Moves, Outcome, ResourceAddr, SubstateKey, TxHash, encode_amount,
};

const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const PAYER: u8 = 0xA1;
const PAYEE: u8 = 0xC1;

/// Any expiry; nothing here reaches one.
const EXPIRY_MS: u64 = 1_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(1_000)
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

const fn owner(byte: u8) -> Address {
    Address::new([byte; 31], AddressClass::Component)
}

fn cell(byte: u8) -> SubstateKey {
    child_key(&TestHasher, owner(byte), SlotId(1), &[])
}

const fn intent() -> SubintentHash {
    SubintentHash(Hash32([0x5A; 32]))
}

fn record_site() -> CrossingSite {
    CrossingSite::record(&TestHasher, owner(PAYER), intent(), 0, 0, EXPIRY_MS)
}

fn claim_site() -> CrossingSite {
    CrossingSite::claim(&TestHasher, owner(PAYEE), intent(), 0, 0, EXPIRY_MS)
}

/// A crossing's cell, as the declaration has to name it.
const fn crossing_cell(site: CrossingSite) -> Effect {
    Effect {
        target: EffectTarget::Point(site.key()),
        mode: Mode::Write { moves: Moves::Both },
    }
}

/// A declaration over the cells a fixture moves value through.
fn moving(set: EffectSet) -> Declaration {
    Declaration::from_set(set).denominated(|effect| {
        matches!(effect.mode, Mode::Delta { .. } | Mode::Reserve { .. }).then_some(RESOURCE)
    })
}

fn declared(effects: &[Effect]) -> Declaration {
    let mut set = EffectSet::new();
    for effect in effects {
        set.insert(*effect).unwrap();
    }
    moving(set)
}

/// One lowered call: what it produces, and what it consumes.
fn call(export: &str, edges: usize, outputs: usize) -> NodeCall {
    NodeCall {
        package: PackageHash(Hash32([0xAB; 32])),
        target: owner(PAYER),
        export: export.into(),
        args: (0..edges)
            .map(|slot| CallArg::Bucket {
                source: 0,
                output: u32::try_from(slot).unwrap(),
            })
            .collect(),
        edges: Vec::new(),
        outputs: vec![EdgeContent::Fungible; outputs],
        issues: Vec::new(),
        evidence: Vec::new(),
        requires: Vec::new(),
    }
}

/// The backend these tests drive: `take` hands the reservation out as an
/// edge, `put` files whatever bucket it was handed into the delta cell.
struct Moving;

impl GuestBackend for Moving {
    fn invoke(&self, mut session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let caps = session.capabilities().to_vec();
        let find = |wanted: fn(&Capability) -> bool| {
            caps.iter()
                .enumerate()
                .find_map(|(rep, cap)| wanted(cap).then(|| u32::try_from(rep).unwrap()))
        };
        let edges = match call.export {
            "take" => {
                let reserve = find(|cap| matches!(cap, Capability::Reserve { .. }))
                    .expect("the fixture declares one");
                vec![session.reserve_take(reserve, 0).unwrap()]
            }
            "put" => {
                let delta = find(|cap| matches!(cap, Capability::Delta { .. }))
                    .expect("the fixture declares one");
                let funds = match call.args.first() {
                    Some(GuestArg::Bucket(rep)) => *rep,
                    _ => panic!("the consumer takes one bucket"),
                };
                session.cell_put(delta, 0, funds).unwrap();
                Vec::new()
            }
            other => panic!("no fixture for {other}"),
        };
        InvokeResult {
            session,
            fuel: 0,
            result: Invoked::Produced {
                edges,
                answer: None,
            },
            exhausted: false,
        }
    }
}

fn run(store: &MemoryStore, entry: BatchTx) -> Receipt {
    let batch = vec![entry];
    let outcome = execute_batch(
        Arc::new(store.clone()) as Arc<dyn Baseline>,
        &batch,
        &ManifestWalk { backend: &Moving },
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    outcome.receipts[&batch[0].tx].clone()
}

/// The sending half: one node reserves, and what it produced departs
/// rather than reaching a local consumer.
fn sending(amount: u128) -> BatchTx {
    let mut legs = LegPlan::whole();
    legs.departs(0, 0, record_site()).unwrap();
    BatchTx::new(
        tx(1),
        declared(&[
            Effect {
                target: EffectTarget::Point(cell(PAYER)),
                mode: Mode::Reserve { amount },
            },
            // The record cell is declared like any other write, which is
            // what puts racing writers of one crossing in a single
            // conflict group — and what keeps this write out of the
            // undeclared-access sweep that halts a shard.
            crossing_cell(record_site()),
        ]),
        env(),
    )
    .with_calls(vec![call("take", 0, 1)])
    .with_legs(legs)
}

/// The receiving half: the producer is a node another shard ran, and
/// what stands in for it is the value that arrived.
fn receiving(crossed: Crossed) -> BatchTx {
    let mut legs = LegPlan::whole();
    legs.skip(0);
    legs.arrives(0, 0, crossed, claim_site()).unwrap();
    BatchTx::new(
        tx(2),
        declared(&[
            Effect {
                target: EffectTarget::Point(cell(PAYEE)),
                mode: Mode::Delta { moves: Moves::Both },
            },
            crossing_cell(claim_site()),
        ]),
        env(),
    )
    .with_calls(vec![call("take", 0, 1), call("put", 1, 0)])
    .with_legs(legs)
}

/// The two halves reconcile without either reading the other: what the
/// sender attests it issued is what the receiver claims, and the record
/// cell the sender committed decodes to the same figure.
#[test]
fn the_two_halves_of_one_crossing_reconcile() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());

    let sent = run(&store, sending(200));
    assert!(
        matches!(sent.outcome, Outcome::Completed { .. }),
        "{sent:?}"
    );
    assert_eq!(sent.escrow.issued(RESOURCE), 200);
    assert_eq!(
        sent.escrow.issues().collect::<Vec<_>>(),
        vec![(
            (0, 0),
            Crossed {
                resource: RESOURCE,
                amount: 200,
            },
        )],
    );

    // The payer's cell moved by exactly what left, and the record cell
    // says what that was.
    let record: CrossingCell = from_slice(
        sent.delta.cells[&record_site().key()]
            .as_deref()
            .expect("the record committed"),
    )
    .expect("a record cell decodes");
    assert_eq!(record.resource, RESOURCE);
    assert_eq!(record.amount, 200);
    assert_eq!(record.expiry_ms, EXPIRY_MS);

    // The receiving half claims exactly that, on its own shard, out of a
    // batch that never saw the sender's session.
    let mut arrived = MemoryStore::new();
    arrived.write(cell(PAYEE), encode_amount(0).to_vec());
    let taken = run(
        &arrived,
        receiving(Crossed {
            resource: record.resource,
            amount: record.amount,
        }),
    );
    assert!(
        matches!(taken.outcome, Outcome::Completed { .. }),
        "{taken:?}"
    );
    assert_eq!(taken.escrow.claimed(RESOURCE), sent.escrow.issued(RESOURCE));

    let claim: ClaimCell = from_slice(
        taken.delta.cells[&claim_site().key()]
            .as_deref()
            .expect("the claim committed"),
    )
    .expect("a claim cell decodes");
    assert_eq!(claim.tx, tx(2));
}

/// Each half conserves where it runs, which is what lets a divided
/// transaction be judged without assembling it: an issue is a gain for
/// the reason a burn is, a claim a loss for the reason a mint is.
#[test]
fn each_half_conserves_on_its_own() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    let sent = run(&store, sending(200));
    assert!(
        matches!(sent.outcome, Outcome::Completed { .. }),
        "{sent:?}"
    );

    let mut arrived = MemoryStore::new();
    arrived.write(cell(PAYEE), encode_amount(10).to_vec());
    let taken = run(
        &arrived,
        receiving(Crossed {
            resource: RESOURCE,
            amount: 200,
        }),
    );
    assert!(
        matches!(taken.outcome, Outcome::Completed { .. }),
        "{taken:?}"
    );
    // The recipient's cell gained exactly the crossing.
    let credited = taken
        .delta
        .movements
        .get(&cell(PAYEE))
        .map(|movement| movement.credit)
        .expect("the consumer credited its cell");
    assert_eq!(credited, 200);
}

/// A zero-amount edge crosses: the record and the claim are derived from
/// the manifest edge, so dropping one would leave the consumer waiting on
/// a bundle whose target set nothing named.
#[test]
fn a_zero_amount_edge_still_crosses() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    let sent = run(&store, sending(0));
    assert!(
        matches!(sent.outcome, Outcome::Completed { .. }),
        "{sent:?}"
    );

    assert!(!sent.escrow.is_empty(), "the edge crossed");
    assert_eq!(sent.escrow.issued(RESOURCE), 0, "and the totals skip it");
    assert_eq!(sent.escrow.issues().count(), 1);
    assert!(sent.delta.cells.contains_key(&record_site().key()));
}

/// A consumer reaching for a slot nothing crossed on meets the ordinary
/// missing-edge refusal — the output table is sized from the node's own
/// declaration, so a plan that named nothing leaves a hole rather than a
/// shorter table.
#[test]
fn an_arrival_that_never_came_is_a_missing_edge() {
    let mut arrived = MemoryStore::new();
    arrived.write(cell(PAYEE), encode_amount(0).to_vec());

    let mut legs = LegPlan::whole();
    legs.skip(0);
    let entry = BatchTx::new(
        tx(3),
        declared(&[Effect {
            target: EffectTarget::Point(cell(PAYEE)),
            mode: Mode::Delta { moves: Moves::Both },
        }]),
        env(),
    )
    .with_calls(vec![call("take", 0, 1), call("put", 1, 0)])
    .with_legs(legs);

    assert_eq!(
        run(&arrived, entry).outcome,
        Outcome::ProtocolError {
            reason: AbortReason::MissingProducerEdge,
        },
    );
}

/// An aborted execution commits no claim, so the crossing stays
/// claimable. The write lands in the layer the rest of the transaction
/// wrote into, which is what makes that fall out of the layering rather
/// than need a guard.
///
/// The abort here is the one the plan names: a claim left in flight is
/// value this execution took in and never put anywhere.
#[test]
fn an_aborted_claim_leaves_the_crossing_claimable() {
    let mut arrived = MemoryStore::new();
    arrived.write(cell(PAYEE), encode_amount(0).to_vec());

    let mut legs = LegPlan::whole();
    legs.skip(0);
    legs.arrives(
        0,
        0,
        Crossed {
            resource: RESOURCE,
            amount: 200,
        },
        claim_site(),
    )
    .unwrap();
    let entry = BatchTx::new(
        tx(4),
        declared(&[
            Effect {
                target: EffectTarget::Point(cell(PAYEE)),
                mode: Mode::Delta { moves: Moves::Both },
            },
            crossing_cell(claim_site()),
        ]),
        env(),
    )
    // The producer is skipped and nothing consumes what arrived, so the
    // bucket is still in hand when the transaction ends.
    .with_calls(vec![call("take", 0, 1)])
    .with_legs(legs);

    let receipt = run(&arrived, entry);
    assert_eq!(
        receipt.outcome,
        Outcome::UserError {
            reason: AbortReason::ValueDropped,
        },
    );
    assert!(
        !receipt.delta.cells.contains_key(&claim_site().key()),
        "an abort writes no claim",
    );
}

/// Nothing crosses in a whole-shape execution, which is what every
/// transaction is until it decomposes.
#[test]
fn a_whole_execution_crosses_nothing() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    store.write(cell(PAYEE), encode_amount(0).to_vec());

    let entry = BatchTx::new(
        tx(5),
        declared(&[
            Effect {
                target: EffectTarget::Point(cell(PAYER)),
                mode: Mode::Reserve { amount: 200 },
            },
            Effect {
                target: EffectTarget::Point(cell(PAYEE)),
                mode: Mode::Delta { moves: Moves::Both },
            },
        ]),
        env(),
    )
    .with_calls(vec![call("take", 0, 1), call("put", 1, 0)]);

    let receipt = run(&store, entry);
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "{receipt:?}"
    );
    assert!(receipt.escrow.is_empty());
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&cell(PAYEE))
            .map(|movement| movement.credit),
        Some(200),
        "the value stayed local, so nothing crossed to carry it",
    );
}

/// The kernel bounds a plan's width itself, because the plan crossed a
/// crate boundary since anything checked it.
#[test]
fn a_plan_past_the_crossing_cap_refuses_at_construction() {
    let mut legs = LegPlan::whole();
    for edge in 0..MAX_CROSSINGS_PER_TX {
        legs.departs(u32::try_from(edge).unwrap(), 0, record_site())
            .unwrap();
    }
    assert!(
        legs.departs(
            u32::try_from(MAX_CROSSINGS_PER_TX).unwrap(),
            0,
            record_site(),
        )
        .is_err()
    );
}
