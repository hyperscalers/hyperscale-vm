//! Per-transaction abort semantics at the batch seams: an uncovered
//! debit, racing debits, and malformed reserve declarations abort exactly
//! the transaction they belong to — the batch itself never fails on user
//! input.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubintentHash,
    SubstateKey, TestHasher, child_key, nullifier_key,
};
use hyperscale_vm_kernel::{
    BatchTx, Capability, EnvInputs, ExecutionMode, KernelSession, MemoryStore, Outcome,
    OverlayStore, RunResult, SubstateStore, TxHash, decode_amount, encode_amount, execute_batch,
};

const FUEL: u64 = 7;

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

fn with_delta(mut set: EffectSet, key: SubstateKey) -> EffectSet {
    set.insert(Effect {
        target: EffectTarget::Point(key),
        mode: Mode::Delta,
    })
    .unwrap();
    set
}

/// The scripted guest: a session with a reserve capability transfers the
/// reserved amount into its delta cell; a session with only a delta
/// capability debits `sub` from it.
fn scripted(sub: u128) -> impl Fn(TxHash, KernelSession) -> RunResult + Sync {
    move |_tx_id, mut session: KernelSession| {
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let reserve = caps.iter().enumerate().find_map(|(rep, c)| match c {
            Capability::Reserve(_) => Some(u32::try_from(rep).unwrap()),
            _ => None,
        });
        let delta = caps.iter().enumerate().find_map(|(rep, c)| match c {
            Capability::Delta(_) => Some(u32::try_from(rep).unwrap()),
            _ => None,
        });
        match (reserve, delta) {
            (Some(reserve), Some(delta)) => {
                let amount = session.reserve_amount(reserve).unwrap();
                session.delta_add(delta, &amount).unwrap();
            }
            (None, Some(delta)) => {
                session.delta_sub(delta, &encode_amount(sub)).unwrap();
            }
            _ => {}
        }
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel: FUEL,
        }
    }
}

fn amount_at(store: &OverlayStore, key: SubstateKey) -> u128 {
    let mut store = store.clone();
    decode_amount(&store.read(key).unwrap().unwrap()).unwrap()
}

#[test]
fn a_debit_below_a_held_reservation_aborts_only_its_transaction() {
    // Balance 50, all of it reserved by the transfer: the racing debit's
    // floor is zero, and its uncovered `Sub` is its own loss.
    let mut store = MemoryStore::new();
    store.write(cell(0xA), encode_amount(50).to_vec()).unwrap();
    store.clear_log();
    let batch = vec![
        BatchTx::new(
            tx(0x01),
            with_delta(point(cell(0xA), Mode::Reserve { amount: 50 }), cell(0xC)),
        ),
        BatchTx::new(tx(0x02), point(cell(0xA), Mode::Delta)),
    ];

    for mode in [ExecutionMode::Serial, ExecutionMode::Parallel] {
        let outcome = execute_batch(
            Arc::new(store.clone()),
            &batch,
            &scripted(10),
            env(),
            test_hash,
            mode,
        )
        .unwrap();
        assert!(matches!(
            outcome.receipts[&tx(0x01)].outcome,
            Outcome::Completed { .. }
        ));
        assert_eq!(
            outcome.receipts[&tx(0x02)].outcome,
            Outcome::Infeasible {
                key: cell(0xA),
                amount: 10,
            }
        );
        assert_eq!(outcome.receipts[&tx(0x02)].fuel, FUEL);
        assert_eq!(amount_at(&outcome.store, cell(0xA)), 0);
        assert_eq!(amount_at(&outcome.store, cell(0xC)), 50);
        assert_eq!(outcome.store.held_reservation(cell(0xA), tx(0x02)), None);
    }
}

#[test]
fn a_covered_debit_completes_beside_a_reservation() {
    let mut store = MemoryStore::new();
    store.write(cell(0xA), encode_amount(60).to_vec()).unwrap();
    store.clear_log();
    let batch = vec![
        BatchTx::new(
            tx(0x01),
            with_delta(point(cell(0xA), Mode::Reserve { amount: 50 }), cell(0xC)),
        ),
        BatchTx::new(tx(0x02), point(cell(0xA), Mode::Delta)),
    ];

    let outcome = execute_batch(
        Arc::new(store),
        &batch,
        &scripted(10),
        env(),
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    assert!(matches!(
        outcome.receipts[&tx(0x01)].outcome,
        Outcome::Completed { .. }
    ));
    assert!(matches!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_at(&outcome.store, cell(0xA)), 0);
    assert_eq!(amount_at(&outcome.store, cell(0xC)), 50);
}

#[test]
fn racing_debits_lose_deterministically_in_canonical_order() {
    // Two compatible debits over one cell that covers either but not both:
    // the canonically later transaction loses at apply, whatever the input
    // order or execution mode.
    let mut store = MemoryStore::new();
    store.write(cell(0xA), encode_amount(20).to_vec()).unwrap();
    store.clear_log();
    let batch = vec![
        BatchTx::new(tx(0x01), point(cell(0xA), Mode::Delta)),
        BatchTx::new(tx(0x02), point(cell(0xA), Mode::Delta)),
    ];
    let mut reversed = batch.clone();
    reversed.reverse();

    for input in [batch, reversed] {
        for mode in [ExecutionMode::Serial, ExecutionMode::Parallel] {
            let outcome = execute_batch(
                Arc::new(store.clone()),
                &input,
                &scripted(15),
                env(),
                test_hash,
                mode,
            )
            .unwrap();
            assert!(matches!(
                outcome.receipts[&tx(0x01)].outcome,
                Outcome::Completed { .. }
            ));
            assert_eq!(
                outcome.receipts[&tx(0x02)].outcome,
                Outcome::Infeasible {
                    key: cell(0xA),
                    amount: 15,
                }
            );
            assert_eq!(outcome.receipts[&tx(0x02)].fuel, FUEL);
            assert_eq!(amount_at(&outcome.store, cell(0xA)), 5);
        }
    }
}

#[test]
fn a_reserve_on_a_locked_or_malformed_cell_aborts_only_its_transaction() {
    let mut store = MemoryStore::new();
    store.write(cell(0xAB), vec![1]).unwrap();
    store.lock(cell(0xAB)).unwrap();
    store.write(cell(0xAC), vec![1, 2, 3]).unwrap();
    store
        .write(cell(0xAD), encode_amount(100).to_vec())
        .unwrap();
    store.clear_log();
    let batch = vec![
        BatchTx::new(
            tx(0x01),
            with_delta(point(cell(0xAB), Mode::Reserve { amount: 10 }), cell(0xC)),
        ),
        BatchTx::new(
            tx(0x02),
            with_delta(point(cell(0xAC), Mode::Reserve { amount: 10 }), cell(0xC)),
        ),
        BatchTx::new(
            tx(0x03),
            with_delta(point(cell(0xAD), Mode::Reserve { amount: 40 }), cell(0xC)),
        ),
    ];

    let outcome = execute_batch(
        Arc::new(store),
        &batch,
        &scripted(0),
        env(),
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    let reason = |id: u8| match &outcome.receipts[&tx(id)].outcome {
        Outcome::UserError { reason } => reason.clone(),
        other => panic!("expected a user error, found {other:?}"),
    };
    assert!(reason(0x01).contains("locked"));
    assert!(reason(0x02).contains("amount cell"));
    assert!(matches!(
        outcome.receipts[&tx(0x03)].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_at(&outcome.store, cell(0xAD)), 60);
    assert_eq!(amount_at(&outcome.store, cell(0xC)), 40);
}

fn nullifier() -> SubstateKey {
    nullifier_key(
        &TestHasher,
        Address([0x77; 16]),
        SubintentHash(Hash32([0x99; 32])),
    )
}

fn nullifier_tx(id: u8) -> BatchTx {
    BatchTx {
        tx: tx(id),
        declared: point(nullifier(), Mode::Write),
        nullifiers: vec![nullifier()],
    }
}

#[test]
fn racing_nullifier_writers_commit_exactly_once() {
    // Two envelopes commit the same signed subintent: both declare the
    // nullifier's exclusive write, so they share a group, and canonical
    // order picks the winner; the loser aborts before running.
    let noop = |_id: TxHash, session: KernelSession| RunResult {
        session,
        outcome: Outcome::Completed { value: None },
        fuel: FUEL,
    };
    let batch = vec![nullifier_tx(0x02), nullifier_tx(0x01)];
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &noop,
        env(),
        test_hash,
        ExecutionMode::Parallel,
    )
    .unwrap();
    assert!(matches!(
        outcome.receipts[&tx(0x01)].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::UserError {
            reason: "subintent nullifier spent".into(),
        }
    );
    // The cell records the consuming transaction.
    let mut store = outcome.store.clone();
    assert_eq!(
        store.read(nullifier()).unwrap(),
        Some(tx(0x01).0.0.to_vec())
    );

    // The next batch still sees it spent.
    let replay = execute_batch(
        Arc::new(outcome.store),
        &[nullifier_tx(0x03)],
        &noop,
        env(),
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    assert_eq!(
        replay.receipts[&tx(0x03)].outcome,
        Outcome::UserError {
            reason: "subintent nullifier spent".into(),
        }
    );
}

#[test]
fn an_aborted_transaction_spends_no_nullifier() {
    // The canonical-first envelope traps; the subintent stays unspent
    // and the second envelope commits it.
    let scripted = |id: TxHash, session: KernelSession| RunResult {
        session,
        outcome: if id == tx(0x01) {
            Outcome::UserError {
                reason: "guest trap".into(),
            }
        } else {
            Outcome::Completed { value: None }
        },
        fuel: FUEL,
    };
    let batch = vec![nullifier_tx(0x01), nullifier_tx(0x02)];
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &scripted,
        env(),
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    assert!(matches!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed { .. }
    ));
    let mut store = outcome.store;
    assert_eq!(
        store.read(nullifier()).unwrap(),
        Some(tx(0x02).0.0.to_vec())
    );
}
