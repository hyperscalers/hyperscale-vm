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
    Baseline, BatchError, BatchOutcome, BatchTx, Capability, Crossed, EnvInputs, ExecutionMode,
    GuestBackend, GuestCall, InvokeResult, Invoked, KernelSession, LegPlan, Locality, ManifestWalk,
    MemoryStore, Receipt, Reclaim, Retire, Substates, decode_amount, execute_batch,
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

/// The sending node's call: its handles are the frame's two cells, the
/// reserve it takes from and the record it writes, and the reserve is
/// what names the cell a departing crossing left.
fn taking() -> NodeCall {
    let mut taking = call("take", 0, 1);
    taking.args.push(CallArg::Site {
        entries: vec![Some(0), Some(1)],
    });
    taking
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
                // A trap is the guest's abort, not the fixture's panic:
                // a consumer handed a bucket somebody already took is a
                // verdict these tests read off the receipt.
                if let Err(trap) = session.cell_put(delta, 0, funds) {
                    return InvokeResult {
                        session,
                        fuel: 0,
                        result: Invoked::Aborted(AbortReason::from(trap)),
                        exhausted: false,
                    };
                }
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

fn execute(
    base: Arc<dyn Baseline>,
    batch: &[BatchTx],
    mode: ExecutionMode,
) -> Result<BatchOutcome, BatchError> {
    execute_batch(
        base,
        batch,
        &ManifestWalk { backend: &Moving },
        test_hash,
        mode,
        &Locality::All,
    )
}

fn run(store: &MemoryStore, entry: BatchTx) -> Receipt {
    let batch = vec![entry];
    let outcome = execute(
        Arc::new(store.clone()) as Arc<dyn Baseline>,
        &batch,
        ExecutionMode::Serial,
    )
    .unwrap();
    outcome.receipts[&batch[0].tx].clone()
}

/// Run `entry`, then run `again` against the state the first left.
fn then(store: &MemoryStore, entry: BatchTx, again: BatchTx) -> Receipt {
    let first = execute(
        Arc::new(store.clone()) as Arc<dyn Baseline>,
        &[entry],
        ExecutionMode::Serial,
    )
    .unwrap();
    let tx = again.tx;
    execute(
        Arc::new(first.store) as Arc<dyn Baseline>,
        &[again],
        ExecutionMode::Serial,
    )
    .unwrap()
    .receipts[&tx]
        .clone()
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
    .with_calls(vec![taking()])
    .with_legs(legs)
}

/// The receiving half: the producer is a node another shard ran, and
/// what stands in for it is the value that arrived.
fn receiving(crossed: Crossed) -> BatchTx {
    receiving_as(tx(2), crossed)
}

fn receiving_as(who: TxHash, crossed: Crossed) -> BatchTx {
    let mut legs = LegPlan::whole();
    legs.skip(0);
    legs.arrives(0, 0, crossed, claim_site()).unwrap();
    BatchTx::new(
        who,
        declared(&[
            Effect {
                target: EffectTarget::Point(cell(PAYEE)),
                mode: Mode::Delta { moves: Moves::Both },
            },
            crossing_cell(claim_site()),
        ]),
        env(),
    )
    .with_calls(vec![taking(), call("put", 1, 0)])
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
    .with_calls(vec![taking(), call("put", 1, 0)])
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
    .with_calls(vec![taking()])
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
    .with_calls(vec![taking(), call("put", 1, 0)]);

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

/// The declaration is what forces racing writers of one crossing into a
/// single conflict group, so a batch that writes a record cell without
/// declaring it is a defect in whoever composed the batch. Undeclared,
/// the write escapes the group and then fails the undeclared-access
/// sweep, which halts the shard instead of refusing the transaction.
#[test]
fn an_undeclared_record_cell_refuses_the_batch() {
    let mut legs = LegPlan::whole();
    legs.departs(0, 0, record_site()).unwrap();
    let entry = BatchTx::new(
        tx(6),
        declared(&[Effect {
            target: EffectTarget::Point(cell(PAYER)),
            mode: Mode::Reserve { amount: 200 },
        }]),
        env(),
    )
    .with_calls(vec![taking()])
    .with_legs(legs);

    assert_eq!(
        execute(
            Arc::new(MemoryStore::new()) as Arc<dyn Baseline>,
            &[entry],
            ExecutionMode::Serial,
        )
        .err(),
        Some(BatchError::UndeclaredCrossingCell {
            tx: tx(6),
            key: record_site().key(),
        }),
    );
}

/// The claim family is screened on the same reading, and it is the half
/// where the group matters most: two transactions reaching for one
/// crossing have to land in one group for either to see the other's
/// write.
#[test]
fn an_undeclared_claim_cell_refuses_the_batch() {
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
        tx(7),
        declared(&[Effect {
            target: EffectTarget::Point(cell(PAYEE)),
            mode: Mode::Delta { moves: Moves::Both },
        }]),
        env(),
    )
    .with_calls(vec![taking(), call("put", 1, 0)])
    .with_legs(legs);

    assert_eq!(
        execute(
            Arc::new(MemoryStore::new()) as Arc<dyn Baseline>,
            &[entry],
            ExecutionMode::Serial,
        )
        .err(),
        Some(BatchError::UndeclaredCrossingCell {
            tx: tx(7),
            key: claim_site().key(),
        }),
    );
}

/// Replaying the sending half finds its own record cell committed and
/// refuses before the node runs — a second issue would debit the
/// producing vault twice and rewrite the record with the bytes already
/// in it.
#[test]
fn a_replayed_issue_finds_its_own_record() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());

    let replayed = then(&store, sending(200), sending(200));
    assert_eq!(
        replayed.outcome,
        Outcome::EscrowAlreadyIssued {
            key: record_site().key(),
        },
    );
    assert_eq!(replayed.fuel, 0, "the node never ran");
    assert!(replayed.delta.cells.is_empty() && replayed.delta.movements.is_empty());
    assert!(replayed.escrow.is_empty(), "and nothing crossed twice");
}

/// The same on the receiving side: a committed claim says the crossing
/// is spent, whoever spent it.
#[test]
fn a_replayed_claim_finds_the_crossing_taken() {
    let crossed = Crossed {
        resource: RESOURCE,
        amount: 200,
    };
    let mut arrived = MemoryStore::new();
    arrived.write(cell(PAYEE), encode_amount(0).to_vec());

    let replayed = then(
        &arrived,
        receiving_as(tx(2), crossed),
        receiving_as(tx(2), crossed),
    );
    assert_eq!(
        replayed.outcome,
        Outcome::EscrowAlreadyClaimed {
            key: claim_site().key(),
        },
    );
    assert_eq!(replayed.fuel, 0, "the node never ran");
    assert!(replayed.delta.movements.is_empty(), "and credited nothing");
}

/// Two transactions reaching for one crossing in a single batch: the
/// declaration puts them in one conflict group, the group runs in
/// canonical order, and the second finds the first's claim. Driven in
/// parallel mode, because that is the arrangement where a crossing not
/// forced into a group would be claimed twice.
///
/// The claim cell is the whole of what groups them — the two also
/// declare one delta target, and deltas commute — so this is the
/// screen's own reason, driven.
#[test]
fn one_crossing_is_claimed_once_across_two_claimers() {
    let crossed = Crossed {
        resource: RESOURCE,
        amount: 200,
    };
    let mut arrived = MemoryStore::new();
    arrived.write(cell(PAYEE), encode_amount(0).to_vec());

    let batch = vec![
        receiving_as(tx(0x21), crossed),
        receiving_as(tx(0x22), crossed),
    ];
    let outcome = execute(
        Arc::new(arrived) as Arc<dyn Baseline>,
        &batch,
        ExecutionMode::Parallel,
    )
    .unwrap();

    assert!(
        matches!(
            outcome.receipts[&tx(0x21)].outcome,
            Outcome::Completed { .. }
        ),
        "{:?}",
        outcome.receipts[&tx(0x21)],
    );
    assert_eq!(
        outcome.receipts[&tx(0x22)].outcome,
        Outcome::EscrowAlreadyClaimed {
            key: claim_site().key(),
        },
    );
    assert_eq!(outcome.receipts[&tx(0x22)].escrow.claimed(RESOURCE), 0);
}

/// Two consumers of one output is a double spend, and running whole is
/// what refuses it: one session hands both consumers the same bucket
/// handle and the second take finds it gone. Admission refuses the
/// shape before a manifest ever reaches here, so this is the line behind
/// that one — and it is the line decomposition would remove, since two
/// consumers on two shards would be two sessions, each taking once. That
/// is why such a shape never decomposes at all.
#[test]
fn a_second_consumer_of_one_edge_is_refused_running_whole() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    store.write(cell(PAYEE), encode_amount(0).to_vec());

    let entry = BatchTx::new(
        tx(8),
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
    // Both consumers name the producer's output 0.
    .with_calls(vec![taking(), call("put", 1, 0), call("put", 1, 0)]);

    let receipt = run(&store, entry);
    assert_eq!(
        receipt.outcome,
        Outcome::UserError {
            reason: AbortReason::HandleUnknown,
        },
    );
    assert!(
        receipt.delta.movements.is_empty(),
        "and nothing was credited"
    );
}

/// The record names the cell the value left — the producing frame's one
/// cell denominated in the crossing's resource — so a reclaim needs
/// nothing but the leaf. A frame holding two such cells names none, and
/// its crossing is nobody's to take back.
#[test]
fn a_record_names_the_cell_its_value_left() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(1_000).to_vec());
    let sent = execute(
        Arc::new(store) as Arc<dyn Baseline>,
        &[sending(200)],
        ExecutionMode::Serial,
    )
    .unwrap();
    let record = CrossingCell::from_bytes(&sent.store.cell(record_site().key()).unwrap()).unwrap();
    assert_eq!(record.origin, Some(cell(PAYER)));

    let mut ambiguous = sending(200);
    ambiguous.declaration = declared(&[
        Effect {
            target: EffectTarget::Point(cell(PAYER)),
            mode: Mode::Reserve { amount: 200 },
        },
        Effect {
            target: EffectTarget::Point(cell(0x77)),
            mode: Mode::Delta { moves: Moves::Both },
        },
        crossing_cell(record_site()),
    ]);
    ambiguous.calls = vec![{
        let mut taking = call("take", 0, 1);
        taking.args.push(CallArg::Site {
            entries: vec![Some(0), Some(1), Some(2)],
        });
        taking
    }];
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(1_000).to_vec());
    store.write(cell(0x77), encode_amount(0).to_vec());
    let sent = execute(
        Arc::new(store) as Arc<dyn Baseline>,
        &[ambiguous],
        ExecutionMode::Serial,
    )
    .unwrap();
    let record = CrossingCell::from_bytes(&sent.store.cell(record_site().key()).unwrap()).unwrap();
    assert_eq!(record.origin, None, "two cells in the resource name none");
    let reclaimed = execute(
        Arc::new(sent.store) as Arc<dyn Baseline>,
        &[reclaiming(tx(9))],
        ExecutionMode::Serial,
    )
    .unwrap();
    assert!(
        matches!(
            reclaimed.receipts[&tx(9)].outcome,
            Outcome::ProtocolError { .. }
        ),
        "a record naming no origin cannot be taken back: {:?}",
        reclaimed.receipts[&tx(9)]
    );
}

/// The reclaim's claim cell, under the producer's own target.
fn reclaim_site() -> CrossingSite {
    CrossingSite::claim(&TestHasher, owner(PAYER), intent(), 0, 0, EXPIRY_MS)
}

/// The producing node taking its own record back: reads the record,
/// claims it under its own target, credits the cell the value left. No
/// node runs.
fn reclaiming(who: TxHash) -> BatchTx {
    let mut legs = LegPlan::whole();
    legs.reclaims(
        0,
        0,
        Reclaim {
            record: record_site().key(),
            claim: reclaim_site(),
        },
    )
    .unwrap();
    BatchTx::new(
        who,
        declared(&[
            crossing_cell(record_site()),
            crossing_cell(reclaim_site()),
            Effect {
                target: EffectTarget::Point(cell(PAYER)),
                mode: Mode::Delta { moves: Moves::Both },
            },
        ]),
        env(),
    )
    .with_legs(legs)
}

fn balance(outcome: &BatchOutcome, key: SubstateKey) -> u128 {
    decode_amount(&outcome.store.cell(key).expect("the cell stands")).unwrap()
}

/// Issue, then reclaim: the producing vault is back at its pre-escrow
/// balance exactly, read off the vault rather than inferred; the claim is
/// a loss and the credit a gain, so the fold balances with no term of
/// its own; and the record goes, since the value it held is back.
#[test]
fn a_reclaim_restores_the_producing_vault_exactly() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());

    let sent = execute(
        Arc::new(store) as Arc<dyn Baseline>,
        &[sending(200)],
        ExecutionMode::Serial,
    )
    .unwrap();
    assert_eq!(
        balance(&sent, cell(PAYER)),
        300,
        "the escrow debited the vault"
    );

    let reclaimed = execute(
        Arc::new(sent.store) as Arc<dyn Baseline>,
        &[reclaiming(tx(9))],
        ExecutionMode::Serial,
    )
    .unwrap();
    let receipt = &reclaimed.receipts[&tx(9)];
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "{receipt:?}"
    );
    assert_eq!(receipt.fuel, 0, "no node ran");
    assert_eq!(receipt.escrow.claimed(RESOURCE), 200);
    assert_eq!(receipt.escrow.issued(RESOURCE), 0);
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&cell(PAYER))
            .map(|movement| movement.credit),
        Some(200),
    );
    assert_eq!(balance(&reclaimed, cell(PAYER)), 500);
    assert!(
        reclaimed.store.cell(record_site().key()).is_none(),
        "the record goes with the value it held",
    );
    let claim: ClaimCell = from_slice(
        reclaimed
            .store
            .cell(reclaim_site().key())
            .as_deref()
            .expect("the claim committed"),
    )
    .unwrap();
    assert_eq!(claim.tx, tx(9));
}

/// A second reclaim of one crossing finds the first's claim and moves
/// nothing — on the machinery that refuses a second claim.
#[test]
fn a_second_reclaim_is_refused_and_moves_nothing() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    let sent = execute(
        Arc::new(store) as Arc<dyn Baseline>,
        &[sending(200)],
        ExecutionMode::Serial,
    )
    .unwrap();
    let once = execute(
        Arc::new(sent.store) as Arc<dyn Baseline>,
        &[reclaiming(tx(9))],
        ExecutionMode::Serial,
    )
    .unwrap();
    let twice = execute(
        Arc::new(once.store) as Arc<dyn Baseline>,
        &[reclaiming(tx(10))],
        ExecutionMode::Serial,
    )
    .unwrap();
    let receipt = &twice.receipts[&tx(10)];
    assert_eq!(
        receipt.outcome,
        Outcome::EscrowAlreadyClaimed {
            key: reclaim_site().key(),
        },
    );
    assert!(receipt.delta.movements.is_empty());
    assert_eq!(balance(&twice, cell(PAYER)), 500);
}

/// The producing node retiring a record whose claim committed: reads
/// the record, deletes it, moves nothing. No node runs.
fn retiring(who: TxHash) -> BatchTx {
    let mut legs = LegPlan::whole();
    legs.retires(
        0,
        0,
        Retire {
            record: record_site(),
        },
    )
    .unwrap();
    BatchTx::new(who, declared(&[crossing_cell(record_site())]), env()).with_legs(legs)
}

/// Issue, then retire: the record is gone, nothing moved, no fold term
/// entered, and the vault stands where the escrow left it.
#[test]
fn a_retire_deletes_the_record_and_moves_nothing() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    let sent = execute(
        Arc::new(store) as Arc<dyn Baseline>,
        &[sending(200)],
        ExecutionMode::Serial,
    )
    .unwrap();
    assert!(sent.store.cell(record_site().key()).is_some());

    let retired = execute(
        Arc::new(sent.store) as Arc<dyn Baseline>,
        &[retiring(tx(12))],
        ExecutionMode::Serial,
    )
    .unwrap();
    let receipt = &retired.receipts[&tx(12)];
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "{receipt:?}"
    );
    assert_eq!(receipt.fuel, 0, "no node ran");
    assert!(receipt.delta.movements.is_empty());
    assert_eq!(receipt.escrow.claimed(RESOURCE), 0);
    assert_eq!(receipt.escrow.issued(RESOURCE), 0);
    assert_eq!(
        receipt.delta.cells.get(&record_site().key()),
        Some(&None),
        "the receipt deletes the record"
    );
    assert!(retired.store.cell(record_site().key()).is_none());
    assert_eq!(
        balance(&retired, cell(PAYER)),
        300,
        "the value stays claimed"
    );
}

/// A second retire finds no record: the batch's defect, refused, and
/// nothing changes.
#[test]
fn a_second_retire_is_refused() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    let sent = execute(
        Arc::new(store) as Arc<dyn Baseline>,
        &[sending(200)],
        ExecutionMode::Serial,
    )
    .unwrap();
    let once = execute(
        Arc::new(sent.store) as Arc<dyn Baseline>,
        &[retiring(tx(12))],
        ExecutionMode::Serial,
    )
    .unwrap();
    let twice = execute(
        Arc::new(once.store) as Arc<dyn Baseline>,
        &[retiring(tx(13))],
        ExecutionMode::Serial,
    )
    .unwrap();
    let receipt = &twice.receipts[&tx(13)];
    assert_eq!(
        receipt.outcome,
        Outcome::ProtocolError {
            reason: AbortReason::EscrowRecordUnreadable,
        },
    );
    assert!(receipt.delta.cells.is_empty());
    assert_eq!(balance(&twice, cell(PAYER)), 300);
}

/// A reclaim reads its record and nothing else, so a record that is not
/// there — or names another edge — is the batch's defect, not a lost
/// race: nothing is credited on a plan's say-so.
#[test]
fn a_reclaim_of_a_record_that_is_not_there_is_a_defect() {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    let receipt = run(&store, reclaiming(tx(11)));
    assert_eq!(
        receipt.outcome,
        Outcome::ProtocolError {
            reason: AbortReason::EscrowRecordUnreadable,
        },
    );
    assert!(receipt.delta.movements.is_empty());
}
