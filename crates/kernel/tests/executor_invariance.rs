//! The batch executor at the kernel level: conflict grouping, canonical
//! application, and schedule invariance, with a scripted runner in place
//! of an engine.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use hyperscale_vm_effects::{Declaration, Hash32, Hasher, SlotId, TestHasher, child_key};
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, Capability, EnvInputs, ExecutionMode, KernelSession, Locality,
    MemoryStore, RunResult, WorkingStore, decode_amount, execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Answer, Effect, EffectSet, EffectTarget, Mode, Movement,
    Outcome, ResourceAddr, SubstateKey, TxHash, encode_amount,
};

/// The one answer a fixture guest hands back, so a receipt depends on
/// something the run can vary.
fn answered(value: u64) -> Vec<Answer> {
    vec![Answer {
        node: 0,
        value: value.to_le_bytes().to_vec(),
    }]
}

/// What every cell these fixtures move value through holds.
const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

/// The declaration a hand-built set stands for.
///
/// A commutative movement names a cell that holds value, and what it
/// holds is the declaration's to say — so a fixture standing in for a
/// signature has to say it too, or the movement is refused before any
/// body runs.
fn moving(set: EffectSet) -> Declaration {
    Declaration::from_set(set).denominated(|effect| {
        matches!(effect.mode, Mode::Delta | Mode::Reserve { .. }).then_some(RESOURCE)
    })
}

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(1_000)
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn cell(byte: u8) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([byte; 31], AddressClass::Component),
        SlotId(1),
        &[],
    )
}

fn point(key: SubstateKey, mode: Mode) -> EffectSet {
    let mut set = EffectSet::new();
    set.insert(Effect {
        target: EffectTarget::Point(key),
        mode,
    })
    .unwrap();
    set
}

fn reserve_and_delta(sender: SubstateKey, amount: u128, recipient: SubstateKey) -> EffectSet {
    let mut set = point(sender, Mode::Reserve { amount });
    set.insert(Effect {
        target: EffectTarget::Point(recipient),
        mode: Mode::Delta,
    })
    .unwrap();
    set
}

fn rep_of(session: &KernelSession, wanted: &Capability) -> u32 {
    u32::try_from(
        session
            .capabilities()
            .iter()
            .position(|c| c == wanted)
            .expect("capability present"),
    )
    .expect("bounded")
}

/// The scripted guest: transfers move the reserved amount into the delta
/// cell; writers bump their cell's first byte; the doomed writer mutates
/// and then fails.
fn scripted(entry: &BatchTx, mut session: KernelSession) -> RunResult {
    let tx_id = entry.tx;
    let caps: Vec<Capability> = session.capabilities().to_vec();
    let reserve = caps.iter().find_map(|c| match c {
        Capability::Reserve { .. } => Some(rep_of(&session, c)),
        _ => None,
    });
    let delta = caps.iter().find_map(|c| match c {
        Capability::Delta(key) => Some(rep_of(&session, &Capability::Delta(*key))),
        _ => None,
    });
    let write = caps.iter().find_map(|c| match c {
        Capability::Write(key) => Some(rep_of(&session, &Capability::Write(*key))),
        _ => None,
    });

    let outcome = if let (Some(reserve), Some(delta)) = (reserve, delta) {
        let amount = session.reserve_amount(reserve, 0).unwrap();
        let funds = session.reserve_take(reserve, 0).unwrap();
        session.cell_put(delta, 0, funds).unwrap();
        Outcome::Completed {
            answers: answered(u64::try_from(amount).unwrap()),
        }
    } else if let Some(write) = write {
        let mut value = session.cell_get(write, 0).unwrap();
        value[0] += 1;
        session.write_cell_set(write, 0, value.clone()).unwrap();
        if tx_id == tx(0x66) {
            // The doomed writer: state must not survive its failure.
            Outcome::UserError {
                reason: AbortReason::Unreachable,
            }
        } else {
            Outcome::Completed {
                answers: answered(u64::from(value[0])),
            }
        }
    } else {
        Outcome::Completed { answers: vec![] }
    };
    let fuel = 10 + u64::from(tx_id.0.0[0]);
    match outcome {
        Outcome::Completed { answers } => RunResult::Completed {
            session,
            answers,
            fuel,
        },
        outcome => RunResult::Aborted {
            session,
            outcome,
            fuel,
        },
    }
}

fn fixture() -> (MemoryStore, Vec<BatchTx>) {
    let mut store = MemoryStore::new();
    store.write(cell(0xA), encode_amount(100).to_vec());
    store.write(cell(0xB), encode_amount(100).to_vec());
    store.write(cell(0xE), vec![10]);
    store.write(cell(0xF), vec![10]);

    let batch = vec![
        // Two transfers into the shared recipient: delta-delta compatible,
        // so they land in different groups and merge by movement.
        BatchTx::new(
            tx(0x01),
            moving(reserve_and_delta(cell(0xA), 40, cell(0xC))),
            env(),
        ),
        BatchTx::new(
            tx(0x02),
            moving(reserve_and_delta(cell(0xB), 25, cell(0xC))),
            env(),
        ),
        // Two writers of one cell: write-write conflict, one group,
        // canonical order.
        BatchTx::new(tx(0x03), moving(point(cell(0xE), Mode::Write)), env()),
        BatchTx::new(tx(0x04), moving(point(cell(0xE), Mode::Write)), env()),
        // Infeasible: the sender vault cannot cover it after tx 0x01.
        BatchTx::new(
            tx(0x05),
            moving(reserve_and_delta(cell(0xA), 1_000, cell(0xC))),
            env(),
        ),
        // The doomed writer on its own cell.
        BatchTx::new(tx(0x66), moving(point(cell(0xF), Mode::Write)), env()),
    ];
    (store, batch)
}

/// A cell's amount, reading an absent cell as zero — the same
/// normalisation every guest applies, and what a drained vault now
/// looks like.
fn amount_at(outcome: &BatchOutcome, key: SubstateKey) -> u128 {
    let mut store = outcome.store.clone();
    store
        .read(key)
        .unwrap()
        .map_or(0, |cell| decode_amount(&cell).unwrap())
}

/// The end state's full cell map, through the collapsed overlay. `base`
/// is the store the batch executed over.
fn collect_cells(outcome: &BatchOutcome, base: &MemoryStore) -> BTreeMap<SubstateKey, Vec<u8>> {
    let store = outcome.store.collapse_onto(base.clone());
    store
        .cells()
        .map(|(key, value)| (key, value.to_vec()))
        .collect()
}

fn bytes_at(outcome: &BatchOutcome, key: SubstateKey) -> Vec<u8> {
    let mut store = outcome.store.clone();
    store.read(key).unwrap().unwrap()
}

#[test]
fn the_batch_semantics_are_exact() {
    let (store, batch) = fixture();
    let outcome = execute_batch(
        Arc::new(store),
        &batch,
        &scripted,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();

    // Settlements and movements composed: senders debited, the shared
    // recipient credited by both transfers.
    assert_eq!(amount_at(&outcome, cell(0xA)), 60);
    assert_eq!(amount_at(&outcome, cell(0xB)), 75);
    assert_eq!(amount_at(&outcome, cell(0xC)), 65);
    // The conflicting writers applied in canonical order.
    assert_eq!(bytes_at(&outcome, cell(0xE)), vec![12]);
    // The doomed writer's mutation never committed.
    assert_eq!(bytes_at(&outcome, cell(0xF)), vec![10]);

    // Receipts carry the taxonomy and movement form.
    assert_eq!(
        outcome.receipts[&tx(0x01)].delta.movements[&cell(0xC)],
        Movement {
            resource: RESOURCE,
            credit: 40,
            debit: 0,
        }
    );
    assert_eq!(
        outcome.receipts[&tx(0x01)].delta.settles[&cell(0xA)].debit,
        40
    );
    assert!(outcome.receipts[&tx(0x01)].delta.cells.is_empty());
    assert!(matches!(
        outcome.receipts[&tx(0x05)].outcome,
        Outcome::Infeasible { amount: 1_000, .. }
    ));
    assert!(matches!(
        outcome.receipts[&tx(0x66)].outcome,
        Outcome::UserError { .. }
    ));
    assert_eq!(
        outcome.receipts[&tx(0x04)].delta.cells[&cell(0xE)],
        Some(vec![12])
    );

    // No reservation is left held anywhere.
    assert_eq!(outcome.store.held_reservation(cell(0xA), tx(0x05)), None);
}

#[test]
fn serial_parallel_and_permuted_timing_agree_byte_for_byte() {
    let (store, batch) = fixture();
    let serial = execute_batch(
        Arc::new(store.clone()),
        &batch,
        &scripted,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    let parallel = execute_batch(
        Arc::new(store.clone()),
        &batch,
        &scripted,
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();
    // Adversarial worker timing: later hashes run eagerly, earlier ones
    // stall, inverting any accidental reliance on arrival order.
    let stalled = |entry: &BatchTx, session: KernelSession| {
        let tx_id = entry.tx;
        sleep(Duration::from_millis(u64::from(
            0xFF_u8.wrapping_sub(tx_id.0.0[0]) / 32,
        )));
        scripted(entry, session)
    };
    let permuted = execute_batch(
        Arc::new(store.clone()),
        &batch,
        &stalled,
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();

    assert_eq!(serial.receipts, parallel.receipts);
    assert_eq!(serial.receipts, permuted.receipts);

    assert_eq!(
        collect_cells(&serial, &store),
        collect_cells(&parallel, &store)
    );
    assert_eq!(
        collect_cells(&serial, &store),
        collect_cells(&permuted, &store)
    );
}

#[test]
fn input_order_cannot_influence_any_receipt() {
    let (store, batch) = fixture();
    let baseline = execute_batch(
        Arc::new(store.clone()),
        &batch,
        &scripted,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();

    let mut reversed = batch.clone();
    reversed.reverse();
    let mut interleaved = batch;
    interleaved.swap(0, 3);
    interleaved.swap(2, 5);
    for permutation in [reversed, interleaved] {
        for mode in [ExecutionMode::Serial, ExecutionMode::Parallel] {
            let outcome = execute_batch(
                Arc::new(store.clone()),
                &permutation,
                &scripted,
                test_hash,
                mode,
                &Locality::All,
            )
            .unwrap();
            assert_eq!(baseline.receipts, outcome.receipts);
            assert_eq!(
                collect_cells(&baseline, &store),
                collect_cells(&outcome, &store)
            );
        }
    }
}

#[test]
fn each_transaction_sees_its_own_clock() {
    // One batch, two clocks: the clock is a per-transaction input — a
    // cross-shard batch mixes transactions committed by different payer
    // blocks — so each session must carry its own entry's value.
    let mut store = MemoryStore::new();
    store.write(cell(0xE), vec![10]);
    store.write(cell(0xF), vec![10]);

    let early = BatchTx::new(
        tx(0x01),
        moving(point(cell(0xE), Mode::Write)),
        EnvInputs::unsealed(1_000),
    );
    let late = BatchTx::new(
        tx(0x02),
        moving(point(cell(0xF), Mode::Write)),
        EnvInputs::unsealed(2_000),
    );

    let observe = |entry: &BatchTx, session: KernelSession| RunResult::Completed {
        answers: answered(session.clock_ms()),
        fuel: u64::from(entry.tx.0.0[0]),
        session,
    };
    let outcome = execute_batch(
        Arc::new(store),
        &[early, late],
        &observe,
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();

    assert_eq!(
        outcome.receipts[&tx(0x01)].outcome,
        Outcome::Completed {
            answers: answered(1_000)
        }
    );
    assert_eq!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed {
            answers: answered(2_000)
        }
    );
}

#[test]
fn each_transaction_sees_its_own_epoch() {
    // The epoch is guest-observable — it is what a seal records — so it
    // reaches the receipt. The two shards of a cross-shard transaction
    // execute it in different batches of different composition, which is
    // why the environment anchors to the transaction and not the batch.
    let mut store = MemoryStore::new();
    store.write(cell(0xE), vec![10]);
    store.write(cell(0xF), vec![10]);

    let at = |epoch| EnvInputs {
        epoch,
        ..EnvInputs::unsealed(env().clock_ms)
    };
    let first = BatchTx::new(tx(0x01), moving(point(cell(0xE), Mode::Write)), at(7));
    let second = BatchTx::new(tx(0x02), moving(point(cell(0xF), Mode::Write)), at(9));

    let observe = |entry: &BatchTx, session: KernelSession| RunResult::Completed {
        answers: answered(session.epoch()),
        fuel: u64::from(entry.tx.0.0[0]),
        session,
    };
    let outcome = execute_batch(
        Arc::new(store),
        &[first, second],
        &observe,
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();

    assert_eq!(
        outcome.receipts[&tx(0x01)].outcome,
        Outcome::Completed {
            answers: answered(7)
        }
    );
    assert_eq!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed {
            answers: answered(9)
        }
    );
}
