//! The batch executor at the kernel level: conflict grouping, canonical
//! application, and schedule invariance, with a scripted runner in place
//! of an engine.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubstateKey,
    TestHasher, child_key,
};
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, Capability, EnvInputs, ExecutionMode, KernelSession, Locality,
    MemoryStore, Movement, Outcome, RunResult, SubstateStore, TxHash, decode_amount, encode_amount,
    execute_batch,
};

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 1_000,
        randomness: [1; 32],
    }
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn cell(byte: u8) -> SubstateKey {
    child_key(&TestHasher, Address([byte; 16]), RoleId(1), &[])
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
fn scripted(tx_id: TxHash, mut session: KernelSession) -> RunResult {
    let caps: Vec<Capability> = session.capabilities().to_vec();
    let reserve = caps
        .iter()
        .find_map(|c| match c {
            Capability::Reserve(key) => Some(*key),
            _ => None,
        })
        .map(|key| rep_of(&session, &Capability::Reserve(key)));
    let delta = caps.iter().find_map(|c| match c {
        Capability::Delta(key) => Some(rep_of(&session, &Capability::Delta(*key))),
        _ => None,
    });
    let write = caps.iter().find_map(|c| match c {
        Capability::Write(key) => Some(rep_of(&session, &Capability::Write(*key))),
        _ => None,
    });

    let outcome = if let (Some(reserve), Some(delta)) = (reserve, delta) {
        let amount = session.reserve_amount(reserve).unwrap();
        session.delta_add(delta, &amount).unwrap();
        Outcome::Completed {
            value: Some(u64::try_from(decode_amount(&amount).unwrap()).unwrap()),
        }
    } else if let Some(write) = write {
        let mut value = session.write_cell_get(write).unwrap();
        value[0] += 1;
        session.write_cell_set(write, value.clone()).unwrap();
        if tx_id == tx(0x66) {
            // The doomed writer: state must not survive its failure.
            Outcome::UserError {
                reason: "scripted defect".into(),
            }
        } else {
            Outcome::Completed {
                value: Some(u64::from(value[0])),
            }
        }
    } else {
        Outcome::Completed { value: None }
    };
    RunResult {
        session,
        outcome,
        fuel: 10 + u64::from(tx_id.0.0[0]),
    }
}

fn fixture() -> (MemoryStore, Vec<BatchTx>) {
    let mut store = MemoryStore::new();
    store.write(cell(0xA), encode_amount(100).to_vec()).unwrap();
    store.write(cell(0xB), encode_amount(100).to_vec()).unwrap();
    store.write(cell(0xE), vec![10]).unwrap();
    store.write(cell(0xF), vec![10]).unwrap();
    store.clear_log();

    let batch = vec![
        // Two transfers into the shared recipient: delta-delta compatible,
        // so they land in different groups and merge by movement.
        BatchTx::new(
            tx(0x01),
            reserve_and_delta(cell(0xA), 40, cell(0xC)),
            env().clock_ms,
            env().randomness,
        ),
        BatchTx::new(
            tx(0x02),
            reserve_and_delta(cell(0xB), 25, cell(0xC)),
            env().clock_ms,
            env().randomness,
        ),
        // Two writers of one cell: write-write conflict, one group,
        // canonical order.
        BatchTx::new(
            tx(0x03),
            point(cell(0xE), Mode::Write),
            env().clock_ms,
            env().randomness,
        ),
        BatchTx::new(
            tx(0x04),
            point(cell(0xE), Mode::Write),
            env().clock_ms,
            env().randomness,
        ),
        // Infeasible: the sender vault cannot cover it after tx 0x01.
        BatchTx::new(
            tx(0x05),
            reserve_and_delta(cell(0xA), 1_000, cell(0xC)),
            env().clock_ms,
            env().randomness,
        ),
        // The doomed writer on its own cell.
        BatchTx::new(
            tx(0x66),
            point(cell(0xF), Mode::Write),
            env().clock_ms,
            env().randomness,
        ),
    ];
    (store, batch)
}

fn amount_at(outcome: &BatchOutcome, key: SubstateKey) -> u128 {
    let mut store = outcome.store.clone();
    decode_amount(&store.read(key).unwrap().unwrap()).unwrap()
}

/// The end state's full cell map, through the collapsed overlay.
fn collect_cells(outcome: &BatchOutcome) -> BTreeMap<SubstateKey, Vec<u8>> {
    let store = outcome.store.clone().collapse();
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
            credit: 40,
            debit: 0,
        }
    );
    assert_eq!(outcome.receipts[&tx(0x01)].delta.settles[&cell(0xA)], 40);
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
    let stalled = |tx_id: TxHash, session: KernelSession| {
        sleep(Duration::from_millis(u64::from(
            0xFF_u8.wrapping_sub(tx_id.0.0[0]) / 32,
        )));
        scripted(tx_id, session)
    };
    let permuted = execute_batch(
        Arc::new(store),
        &batch,
        &stalled,
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();

    assert_eq!(serial.receipts, parallel.receipts);
    assert_eq!(serial.receipts, permuted.receipts);

    assert_eq!(collect_cells(&serial), collect_cells(&parallel));
    assert_eq!(collect_cells(&serial), collect_cells(&permuted));
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
            assert_eq!(collect_cells(&baseline), collect_cells(&outcome));
        }
    }
}

#[test]
fn each_transaction_sees_its_own_clock() {
    // One batch, two clocks: the clock is a per-transaction input — a
    // cross-shard batch mixes transactions committed by different payer
    // blocks — so each session must carry its own entry's value.
    let mut store = MemoryStore::new();
    store.write(cell(0xE), vec![10]).unwrap();
    store.write(cell(0xF), vec![10]).unwrap();
    store.clear_log();

    let early = BatchTx::new(
        tx(0x01),
        point(cell(0xE), Mode::Write),
        1_000,
        env().randomness,
    );
    let late = BatchTx::new(
        tx(0x02),
        point(cell(0xF), Mode::Write),
        2_000,
        env().randomness,
    );

    let observe = |tx_id: TxHash, session: KernelSession| RunResult {
        outcome: Outcome::Completed {
            value: Some(session.clock_ms()),
        },
        session,
        fuel: u64::from(tx_id.0.0[0]),
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
        Outcome::Completed { value: Some(1_000) }
    );
    assert_eq!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed { value: Some(2_000) }
    );
}

#[test]
fn each_transaction_sees_its_own_draw() {
    // Randomness is guest-observable, so it reaches the receipt. The two
    // shards of a cross-shard transaction execute it in different batches
    // of different composition, which is why the draw anchors to the
    // transaction and not to the batch.
    let mut store = MemoryStore::new();
    store.write(cell(0xE), vec![10]).unwrap();
    store.write(cell(0xF), vec![10]).unwrap();
    store.clear_log();

    let first = BatchTx::new(
        tx(0x01),
        point(cell(0xE), Mode::Write),
        env().clock_ms,
        [7; 32],
    );
    let second = BatchTx::new(
        tx(0x02),
        point(cell(0xF), Mode::Write),
        env().clock_ms,
        [9; 32],
    );

    let observe = |tx_id: TxHash, session: KernelSession| RunResult {
        outcome: Outcome::Completed {
            value: Some(u64::from(session.randomness()[0])),
        },
        session,
        fuel: u64::from(tx_id.0.0[0]),
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
        Outcome::Completed { value: Some(7) }
    );
    assert_eq!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed { value: Some(9) }
    );
}
