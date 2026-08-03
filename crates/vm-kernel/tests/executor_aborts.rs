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
    BatchError, BatchTx, Capability, EnvInputs, ExecutionMode, KernelSession, Locality,
    MemoryStore, Outcome, OverlayStore, RunResult, SubstateStore, TxHash, decode_amount,
    encode_amount, execute_batch,
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

/// A cell's amount, reading an absent cell as zero — the same
/// normalisation every guest applies, and what a drained vault now
/// looks like.
fn amount_at(store: &OverlayStore, key: SubstateKey) -> u128 {
    let mut store = store.clone();
    store
        .read(key)
        .unwrap()
        .map_or(0, |cell| decode_amount(&cell).unwrap())
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
            env().clock_ms,
            env().randomness,
        ),
        BatchTx::new(
            tx(0x02),
            point(cell(0xA), Mode::Delta),
            env().clock_ms,
            env().randomness,
        ),
    ];

    for mode in [ExecutionMode::Serial, ExecutionMode::Parallel] {
        let outcome = execute_batch(
            Arc::new(store.clone()),
            &batch,
            &scripted(10),
            test_hash,
            mode,
            &Locality::All,
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
            env().clock_ms,
            env().randomness,
        ),
        BatchTx::new(
            tx(0x02),
            point(cell(0xA), Mode::Delta),
            env().clock_ms,
            env().randomness,
        ),
    ];

    let outcome = execute_batch(
        Arc::new(store),
        &batch,
        &scripted(10),
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
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
        BatchTx::new(
            tx(0x01),
            point(cell(0xA), Mode::Delta),
            env().clock_ms,
            env().randomness,
        ),
        BatchTx::new(
            tx(0x02),
            point(cell(0xA), Mode::Delta),
            env().clock_ms,
            env().randomness,
        ),
    ];
    let mut reversed = batch.clone();
    reversed.reverse();

    for input in [batch, reversed] {
        for mode in [ExecutionMode::Serial, ExecutionMode::Parallel] {
            let outcome = execute_batch(
                Arc::new(store.clone()),
                &input,
                &scripted(15),
                test_hash,
                mode,
                &Locality::All,
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
            env().clock_ms,
            env().randomness,
        ),
        BatchTx::new(
            tx(0x02),
            with_delta(point(cell(0xAC), Mode::Reserve { amount: 10 }), cell(0xC)),
            env().clock_ms,
            env().randomness,
        ),
        BatchTx::new(
            tx(0x03),
            with_delta(point(cell(0xAD), Mode::Reserve { amount: 40 }), cell(0xC)),
            env().clock_ms,
            env().randomness,
        ),
    ];

    let outcome = execute_batch(
        Arc::new(store),
        &batch,
        &scripted(0),
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
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
        ordered: point(nullifier(), Mode::Write).iter().collect(),
        nullifiers: vec![nullifier()],
        clock_ms: env().clock_ms,
        randomness: env().randomness,
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
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
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
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
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
fn a_drained_vault_leaves_no_cell() {
    // Storage is a refundable per-byte bond, so the leaf has to go when
    // the balance does. A commutative cell has no other exit: a delta
    // capability cannot remove, so draining is the only shrink there is.
    let mut store = MemoryStore::new();
    store.write(cell(0xA), encode_amount(50).to_vec()).unwrap();
    store.clear_log();

    // Settling the whole balance away, and moving the whole balance away,
    // are the two ways a cell reaches zero.
    let batch = vec![
        BatchTx::new(
            tx(0x01),
            with_delta(point(cell(0xA), Mode::Reserve { amount: 50 }), cell(0xC)),
            env().clock_ms,
            env().randomness,
        ),
        BatchTx::new(
            tx(0x02),
            point(cell(0xD), Mode::Delta),
            env().clock_ms,
            env().randomness,
        ),
    ];
    let outcome = execute_batch(
        Arc::new(store),
        &batch,
        &scripted(0),
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();

    let mut end = outcome.store.clone();
    assert_eq!(end.read(cell(0xA)).unwrap(), None, "the settled vault");
    assert_eq!(
        end.read(cell(0xD)).unwrap(),
        None,
        "a cell that only ever held zero is never created"
    );
    // The recipient kept its balance, so this is deletion on zero and not
    // deletion on touch.
    assert_eq!(amount_at(&outcome.store, cell(0xC)), 50);

    // Crediting a deleted cell brings it back, and the arithmetic never
    // saw a difference: absent reads as zero throughout.
    let refilled = execute_batch(
        Arc::new(outcome.store.collapse()),
        &[BatchTx::new(
            tx(0x03),
            with_delta(point(cell(0xC), Mode::Reserve { amount: 20 }), cell(0xA)),
            env().clock_ms,
            env().randomness,
        )],
        &scripted(0),
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    assert_eq!(amount_at(&refilled.store, cell(0xA)), 20);
    assert_eq!(amount_at(&refilled.store, cell(0xC)), 30);
}

#[test]
fn a_nullifier_outside_the_declaration_refuses_the_batch() {
    // Once-only safety rests on the declared exclusive write: without it
    // two committing envelopes fall into different conflict groups, each
    // checks its own isolated store, and both spend the same subintent.
    // The batch refuses rather than run.
    let noop = |_id: TxHash, session: KernelSession| RunResult {
        session,
        outcome: Outcome::Completed { value: None },
        fuel: FUEL,
    };
    // A read is not the write the conflict relation needs.
    let undeclared = BatchTx {
        tx: tx(0x01),
        declared: point(nullifier(), Mode::Read),
        ordered: point(nullifier(), Mode::Read).iter().collect(),
        nullifiers: vec![nullifier()],
        clock_ms: env().clock_ms,
        randomness: env().randomness,
    };
    let refused = execute_batch(
        Arc::new(MemoryStore::new()),
        &[undeclared],
        &noop,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    );
    assert_eq!(
        refused.err(),
        Some(BatchError::UndeclaredNullifier {
            tx: tx(0x01),
            key: nullifier(),
        })
    );
}

#[test]
fn declaration_views_that_disagree_refuse_the_batch() {
    // The set and the clause list are one declaration seen two ways, and
    // different consumers read different views — scheduling and judging
    // the set, capability materialization the list. A caller building the
    // struct literally can pair them wrongly, and the consequence would
    // be a transaction routed against one declaration and handed
    // capabilities for another. The batch refuses rather than run.
    let noop = |_id: TxHash, session: KernelSession| RunResult {
        session,
        outcome: Outcome::Completed { value: None },
        fuel: FUEL,
    };
    let mismatched = BatchTx {
        tx: tx(0x01),
        declared: point(cell(0xA), Mode::Write),
        // A different cell entirely: folding this does not reproduce
        // `declared`.
        ordered: point(cell(0xB), Mode::Write).iter().collect(),
        nullifiers: vec![],
        clock_ms: env().clock_ms,
        randomness: env().randomness,
    };
    let refused = execute_batch(
        Arc::new(MemoryStore::new()),
        &[mismatched],
        &noop,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    );
    assert_eq!(
        refused.err(),
        Some(BatchError::InconsistentDeclaration { tx: tx(0x01) })
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
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
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

#[test]
fn a_poisoned_amount_cell_aborts_only_the_delta_that_declared_it() {
    // A write capability grants arbitrary bytes, so a transaction can
    // leave a cell that is not an amount cell. A later delta on it cannot
    // fold — but that is a declaration defect belonging to the delta,
    // exactly as an unusable reserve target is, and must not take the
    // batch down with it.
    let poisoned = cell(0xE);
    let mut store = MemoryStore::new();
    store.write(poisoned, encode_amount(100).to_vec()).unwrap();
    store.clear_log();

    let writer = |_id: TxHash, mut session: KernelSession| {
        let rep = session
            .capabilities()
            .iter()
            .position(|c| matches!(c, Capability::Write(_)))
            .map(|rep| u32::try_from(rep).unwrap());
        if let Some(rep) = rep {
            // One byte: a legal write, an illegal amount cell.
            session.write_cell_set(rep, vec![7]).unwrap();
        }
        let delta = session
            .capabilities()
            .iter()
            .position(|c| matches!(c, Capability::Delta(_)))
            .map(|rep| u32::try_from(rep).unwrap());
        if let Some(rep) = delta {
            session.delta_add(rep, &encode_amount(1)).unwrap();
        }
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel: FUEL,
        }
    };

    let outcome = execute_batch(
        Arc::new(store),
        &[
            BatchTx::new(
                tx(0x01),
                point(poisoned, Mode::Write),
                env().clock_ms,
                env().randomness,
            ),
            BatchTx::new(
                tx(0x02),
                point(poisoned, Mode::Delta),
                env().clock_ms,
                env().randomness,
            ),
        ],
        &writer,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .expect("one bad cell must not fail the batch");

    // The writer got its write; the delta lost only itself.
    assert!(matches!(
        outcome.receipts[&tx(0x01)].outcome,
        Outcome::Completed { .. }
    ));
    match &outcome.receipts[&tx(0x02)].outcome {
        Outcome::UserError { reason } => assert!(reason.contains("amount cell"), "{reason}"),
        other => panic!("expected a user error, found {other:?}"),
    }
}

#[test]
fn a_write_below_a_held_reservation_aborts_only_the_reserver() {
    // A write capability is absolute, so it can lower an amount cell past
    // a reservation another transaction still holds. Write conflicts with
    // reserve, so the two share a conflict group and run in canonical
    // order — and the reserver, whose settle no longer has a floor, loses
    // that race alone. The batch's other work stands.
    let vault = cell(0xB);
    let mut store = MemoryStore::new();
    store.write(vault, encode_amount(100).to_vec()).unwrap();
    store.clear_log();

    let scripted = |_id: TxHash, mut session: KernelSession| {
        let caps: Vec<Capability> = session.capabilities().to_vec();
        for (rep, capability) in caps.iter().enumerate() {
            let rep = u32::try_from(rep).unwrap();
            match capability {
                Capability::Write(_) => {
                    session
                        .write_cell_set(rep, encode_amount(10).to_vec())
                        .unwrap();
                }
                Capability::Reserve(_) => {
                    session.reserve_amount(rep).unwrap();
                }
                _ => {}
            }
        }
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel: FUEL,
        }
    };

    let outcome = execute_batch(
        Arc::new(store),
        &[
            BatchTx::new(
                tx(0x01),
                point(vault, Mode::Write),
                env().clock_ms,
                env().randomness,
            ),
            BatchTx::new(
                tx(0x02),
                point(vault, Mode::Reserve { amount: 100 }),
                env().clock_ms,
                env().randomness,
            ),
        ],
        &scripted,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .expect("an unbacked reservation must not fail the batch");

    assert!(matches!(
        outcome.receipts[&tx(0x01)].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Infeasible {
            key: vault,
            amount: 100,
        }
    );
    // The write landed, and the reservation it undercut released rather
    // than settling.
    assert_eq!(amount_at(&outcome.store, vault), 10);
    assert_eq!(outcome.store.held_reservation(vault, tx(0x02)), None);
}

#[test]
fn movement_totals_past_the_cell_width_abort_only_their_own_transaction() {
    // A delta capability queues whatever the guest asks for, so a guest
    // can credit past `u128` in total. That is its own arithmetic, and
    // the batch carries on without it.
    let vault = cell(0xC);
    let overflowing = |id: TxHash, mut session: KernelSession| {
        if id == tx(0x01) {
            let rep = session
                .capabilities()
                .iter()
                .position(|c| matches!(c, Capability::Delta(_)))
                .map(|rep| u32::try_from(rep).unwrap())
                .expect("a delta capability");
            session.delta_add(rep, &encode_amount(u128::MAX)).unwrap();
            session.delta_add(rep, &encode_amount(u128::MAX)).unwrap();
        }
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel: FUEL,
        }
    };

    let outcome = execute_batch(
        Arc::new(MemoryStore::new()),
        &[
            BatchTx::new(
                tx(0x01),
                point(vault, Mode::Delta),
                env().clock_ms,
                env().randomness,
            ),
            BatchTx::new(
                tx(0x02),
                point(cell(0xD), Mode::Read),
                env().clock_ms,
                env().randomness,
            ),
        ],
        &overflowing,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .expect("one guest's arithmetic must not fail the batch");

    match &outcome.receipts[&tx(0x01)].outcome {
        Outcome::UserError { reason } => assert!(reason.contains("overflow"), "{reason}"),
        other => panic!("expected a user error, found {other:?}"),
    }
    assert!(matches!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_at(&outcome.store, vault), 0);
}
