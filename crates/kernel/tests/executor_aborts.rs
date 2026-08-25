//! Per-transaction abort semantics at the batch seams: an uncovered
//! debit, racing debits, and malformed reserve declarations abort exactly
//! the transaction they belong to — the batch itself never fails on user
//! input.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Declaration, DeclaredAccess, Hash32, Hasher, ResourceKind, SlotId, SubintentHash, TestHasher,
    child_key, nullifier_key,
};
use hyperscale_vm_kernel::{
    BatchError, BatchTx, Capability, EnvInputs, ExecutionMode, GuestRunner, KernelSession,
    Locality, MemoryStore, OverlayStore, RunResult, Unavailable, WorkingStore, decode_amount,
    execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Effect, EffectSet, EffectTarget, ISSUER_REP, Mode, Outcome,
    ResourceAddr, SubstateKey, TxHash, encode_amount,
};

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

const FUEL: u64 = 7;

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

fn with_delta(mut set: EffectSet, key: SubstateKey) -> EffectSet {
    set.insert(Effect {
        target: EffectTarget::Point(key),
        mode: Mode::Delta,
    })
    .unwrap();
    set
}

/// The scripted guest: a session with a reserve capability takes its
/// grant and files it in the delta cell; a session with only a delta
/// capability debits `sub` from it.
///
/// The transfer goes through the bucket rather than reading the amount
/// and crediting it by hand, because taking the grant is what spends the
/// hold — a body that only reads it leaves the cell whole, and would be
/// crediting one cell against a debit that never happened.
fn scripted(sub: u128) -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
    move |_tx_id, mut session: KernelSession| {
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let reserve = caps.iter().enumerate().find_map(|(rep, c)| match c {
            Capability::Reserve { .. } => Some(u32::try_from(rep).unwrap()),
            _ => None,
        });
        let delta = caps.iter().enumerate().find_map(|(rep, c)| match c {
            Capability::Delta(_) => Some(u32::try_from(rep).unwrap()),
            _ => None,
        });
        match (reserve, delta) {
            (Some(reserve), Some(delta)) => {
                let funds = session.reserve_take(reserve).unwrap();
                session.cell_put(delta, funds).unwrap();
            }
            // Taken through the bucket and burned: a debit with no
            // destination is value the transaction lost, which is not
            // what this fixture is about.
            (None, Some(delta)) => {
                session.grant_issuance(RESOURCE, ResourceKind::Fungible);
                let taken = session.cell_take(delta, sub).unwrap();
                session.burn(ISSUER_REP, taken).unwrap();
            }
            _ => {}
        }
        RunResult::Completed {
            session,
            answers: vec![],
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
    store.write(cell(0xA), encode_amount(50).to_vec());
    let batch = vec![
        BatchTx::new(
            tx(0x01),
            moving(with_delta(
                point(cell(0xA), Mode::Reserve { amount: 50 }),
                cell(0xC),
            )),
            env(),
        ),
        BatchTx::new(tx(0x02), moving(point(cell(0xA), Mode::Delta)), env()),
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
    store.write(cell(0xA), encode_amount(60).to_vec());
    let batch = vec![
        BatchTx::new(
            tx(0x01),
            moving(with_delta(
                point(cell(0xA), Mode::Reserve { amount: 50 }),
                cell(0xC),
            )),
            env(),
        ),
        BatchTx::new(tx(0x02), moving(point(cell(0xA), Mode::Delta)), env()),
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
    store.write(cell(0xA), encode_amount(20).to_vec());
    let batch = vec![
        BatchTx::new(tx(0x01), moving(point(cell(0xA), Mode::Delta)), env()),
        BatchTx::new(tx(0x02), moving(point(cell(0xA), Mode::Delta)), env()),
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
fn a_reserve_on_a_malformed_cell_aborts_only_its_transaction() {
    let mut store = MemoryStore::new();
    store.write(cell(0xAC), vec![1, 2, 3]);
    store.write(cell(0xAD), encode_amount(100).to_vec());
    let batch = vec![
        BatchTx::new(
            tx(0x02),
            moving(with_delta(
                point(cell(0xAC), Mode::Reserve { amount: 10 }),
                cell(0xC),
            )),
            env(),
        ),
        BatchTx::new(
            tx(0x03),
            moving(with_delta(
                point(cell(0xAD), Mode::Reserve { amount: 40 }),
                cell(0xC),
            )),
            env(),
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
        Outcome::UserError { reason } => *reason,
        other => panic!("expected a user error, found {other:?}"),
    };
    assert_eq!(reason(0x02), AbortReason::MalformedAmountCell);
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
        Address::new([0x77; 31], AddressClass::Component),
        SubintentHash(Hash32([0x99; 32])),
    )
}

fn nullifier_tx(id: u8) -> BatchTx {
    BatchTx {
        tx: tx(id),
        declaration: Declaration::from_set(point(nullifier(), Mode::Write)),
        calls: Vec::new(),
        nullifiers: vec![nullifier()],
        env: env(),
        gas_limit: u64::MAX,
    }
}

#[test]
fn racing_nullifier_writers_commit_exactly_once() {
    // Two envelopes commit the same signed subintent: both declare the
    // nullifier's exclusive write, so they share a group, and canonical
    // order picks the winner; the loser aborts before running.
    let noop = |_entry: &BatchTx, session: KernelSession| RunResult::Completed {
        session,
        answers: vec![],
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
        Outcome::NullifierSpent { key: nullifier() }
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
        Outcome::NullifierSpent { key: nullifier() }
    );
}

#[test]
fn a_drained_vault_leaves_no_cell() {
    // Storage is a refundable per-byte bond, so the leaf has to go when
    // the balance does. A commutative cell has no other exit: a delta
    // capability cannot remove, so draining is the only shrink there is.
    let mut store = MemoryStore::new();
    store.write(cell(0xA), encode_amount(50).to_vec());

    // Settling the whole balance away, and moving the whole balance away,
    // are the two ways a cell reaches zero.
    let batch = vec![
        BatchTx::new(
            tx(0x01),
            moving(with_delta(
                point(cell(0xA), Mode::Reserve { amount: 50 }),
                cell(0xC),
            )),
            env(),
        ),
        BatchTx::new(tx(0x02), moving(point(cell(0xD), Mode::Delta)), env()),
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
        Arc::new(outcome.store),
        &[BatchTx::new(
            tx(0x03),
            moving(with_delta(
                point(cell(0xC), Mode::Reserve { amount: 20 }),
                cell(0xA),
            )),
            env(),
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
    let noop = |_entry: &BatchTx, session: KernelSession| RunResult::Completed {
        session,
        answers: vec![],
        fuel: FUEL,
    };
    // A read is not the write the conflict relation needs.
    let undeclared = BatchTx {
        tx: tx(0x01),
        declaration: Declaration::from_set(point(nullifier(), Mode::Read)),
        calls: Vec::new(),
        nullifiers: vec![nullifier()],
        env: env(),
        gas_limit: u64::MAX,
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
    let noop = |_entry: &BatchTx, session: KernelSession| RunResult::Completed {
        session,
        answers: vec![],
        fuel: FUEL,
    };
    let mismatched = BatchTx {
        tx: tx(0x01),
        declaration: Declaration {
            set: point(cell(0xA), Mode::Write),
            // A different cell entirely: folding this does not reproduce
            // the set beside it.
            ordered: point(cell(0xB), Mode::Write)
                .iter()
                .map(|effect| DeclaredAccess {
                    effect,
                    holds: None,
                })
                .collect(),
            ..Declaration::default()
        },
        calls: Vec::new(),
        nullifiers: vec![],
        env: env(),
        gas_limit: u64::MAX,
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
    let scripted = |entry: &BatchTx, session: KernelSession| {
        if entry.tx == tx(0x01) {
            RunResult::Aborted {
                session,
                outcome: Outcome::UserError {
                    reason: AbortReason::Unreachable,
                },
                fuel: FUEL,
            }
        } else {
            RunResult::Completed {
                session,
                answers: vec![],
                fuel: FUEL,
            }
        }
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
    store.write(poisoned, encode_amount(100).to_vec());

    let writer = |_entry: &BatchTx, mut session: KernelSession| {
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
            session.delta_add(rep, 1).unwrap();
        }
        RunResult::Completed {
            session,
            answers: vec![],
            fuel: FUEL,
        }
    };

    let outcome = execute_batch(
        Arc::new(store),
        &[
            BatchTx::new(tx(0x01), moving(point(poisoned, Mode::Write)), env()),
            BatchTx::new(tx(0x02), moving(point(poisoned, Mode::Delta)), env()),
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
        Outcome::UserError { reason } => assert_eq!(*reason, AbortReason::MalformedAmountCell),
        other => panic!("expected a user error, found {other:?}"),
    }
}

/// A hold is a floor an exclusive debit meets too.
///
/// The reserver bought a floor and the kernel held it, so a debit
/// crossing it loses whatever mode it came through. That an exclusive
/// one used to win was a consequence of an absolute being judged
/// against nothing — and a value cell stopped being written down that
/// way, so the exception went with it.
///
/// Priced as the lost race it is rather than as the writer's own
/// arithmetic: what stood in its way is another transaction's claim,
/// which nothing in its own body could have seen.
#[test]
fn an_exclusive_debit_past_a_hold_loses_to_the_reserver() {
    let vault = cell(0xB);
    let sink = cell(0xC);
    let mut store = MemoryStore::new();
    store.write(vault, encode_amount(100).to_vec());

    // Every cell holds value here, so the vault's exclusive clause is a
    // value handle rather than a byte one — which is the whole subject.
    let holding = |set: EffectSet| Declaration::from_set(set).denominated(|_| Some(RESOURCE));

    let scripted = |_entry: &BatchTx, mut session: KernelSession| {
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let delta = caps.iter().enumerate().find_map(|(rep, c)| match c {
            Capability::Delta(_) => Some(u32::try_from(rep).unwrap()),
            _ => None,
        });
        for (rep, capability) in caps.iter().enumerate() {
            let rep = u32::try_from(rep).unwrap();
            match capability {
                // The whole balance, exclusively — which the hold
                // standing on the cell leaves none of.
                Capability::Amount(_) => {
                    let funds = session.cell_take(rep, 100).unwrap();
                    session.grant_issuance(RESOURCE, ResourceKind::Fungible);
                    session.burn(ISSUER_REP, funds).unwrap();
                }
                Capability::Reserve { .. } => {
                    let funds = session.reserve_take(rep).unwrap();
                    session
                        .cell_put(delta.expect("the reserver has somewhere to file"), funds)
                        .unwrap();
                }
                _ => {}
            }
        }
        RunResult::Completed {
            session,
            answers: vec![],
            fuel: FUEL,
        }
    };

    let outcome = execute_batch(
        Arc::new(store),
        &[
            BatchTx::new(tx(0x01), holding(point(vault, Mode::Write)), env()),
            BatchTx::new(
                tx(0x02),
                holding(with_delta(
                    point(vault, Mode::Reserve { amount: 100 }),
                    sink,
                )),
                env(),
            ),
        ],
        &scripted,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .expect("a crossed floor is one transaction's loss, not the batch's");

    assert_eq!(
        outcome.receipts[&tx(0x01)].outcome,
        Outcome::Infeasible {
            key: vault,
            amount: 100,
        },
        "the writer crossed a floor it did not buy"
    );
    assert!(matches!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed { .. }
    ));
    // The reserver spent what it held, and nothing else reached the cell.
    assert_eq!(amount_at(&outcome.store, vault), 0);
    assert_eq!(amount_at(&outcome.store, sink), 100);
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
    store.write(vault, encode_amount(100).to_vec());

    let scripted = |_entry: &BatchTx, mut session: KernelSession| {
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let delta = caps.iter().enumerate().find_map(|(rep, c)| match c {
            Capability::Delta(_) => Some(u32::try_from(rep).unwrap()),
            _ => None,
        });
        for (rep, capability) in caps.iter().enumerate() {
            let rep = u32::try_from(rep).unwrap();
            match capability {
                Capability::Write(_) => {
                    session
                        .write_cell_set(rep, encode_amount(10).to_vec())
                        .unwrap();
                }
                // Taken, not merely read: an undercut reservation is only
                // a loss for a transaction that meant to spend it.
                Capability::Reserve { .. } => {
                    let funds = session.reserve_take(rep).unwrap();
                    session
                        .cell_put(delta.expect("the reserver has somewhere to file"), funds)
                        .unwrap();
                }
                _ => {}
            }
        }
        RunResult::Completed {
            session,
            answers: vec![],
            fuel: FUEL,
        }
    };

    let outcome = execute_batch(
        Arc::new(store),
        &[
            BatchTx::new(tx(0x01), moving(point(vault, Mode::Write)), env()),
            BatchTx::new(
                tx(0x02),
                moving(with_delta(
                    point(vault, Mode::Reserve { amount: 100 }),
                    cell(0xC),
                )),
                env(),
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
    let overflowing = |entry: &BatchTx, mut session: KernelSession| {
        if entry.tx == tx(0x01) {
            let rep = session
                .capabilities()
                .iter()
                .position(|c| matches!(c, Capability::Delta(_)))
                .map(|rep| u32::try_from(rep).unwrap())
                .expect("a delta capability");
            session.delta_add(rep, u128::MAX).unwrap();
            session.delta_add(rep, u128::MAX).unwrap();
        }
        RunResult::Completed {
            session,
            answers: vec![],
            fuel: FUEL,
        }
    };

    let outcome = execute_batch(
        Arc::new(MemoryStore::new()),
        &[
            BatchTx::new(tx(0x01), moving(point(vault, Mode::Delta)), env()),
            BatchTx::new(tx(0x02), moving(point(cell(0xD), Mode::Read)), env()),
        ],
        &overflowing,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .expect("one guest's arithmetic must not fail the batch");

    match &outcome.receipts[&tx(0x01)].outcome {
        Outcome::UserError { reason } => assert_eq!(*reason, AbortReason::DeltaTotalOverflow),
        other => panic!("expected a user error, found {other:?}"),
    }
    assert!(matches!(
        outcome.receipts[&tx(0x02)].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_at(&outcome.store, vault), 0);
}

/// An engine with nothing behind it: every invocation finds the
/// environment wanting.
struct Downed;

impl GuestRunner for Downed {
    fn run(&self, _entry: &BatchTx, _session: KernelSession) -> Result<RunResult, Unavailable> {
        Err(Unavailable(AbortReason::CodeUnavailable))
    }
}

#[test]
fn an_unavailable_engine_refuses_the_batch() {
    let mut store = MemoryStore::new();
    store.write(cell(0xA), encode_amount(60).to_vec());
    let batch = vec![BatchTx::new(
        tx(0x01),
        moving(with_delta(
            point(cell(0xA), Mode::Reserve { amount: 50 }),
            cell(0xC),
        )),
        env(),
    )];

    // Machine-local failure is not a verdict: no receipt exists to price
    // it, and the batch refuses rather than letting this node attest
    // something its peers would not reproduce.
    let refused = execute_batch(
        Arc::new(store),
        &batch,
        &Downed,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .expect_err("a machine-local failure is not an outcome");
    assert!(matches!(
        refused,
        BatchError::Unavailable {
            tx: hash,
            reason: AbortReason::CodeUnavailable,
        } if hash == tx(0x01)
    ));
}

/// A transaction that lost value aborts alone, and its batch carries on.
///
/// The abort is priced to nobody — it names the kernel, not the sender —
/// so the two properties are one question: if such a transaction could
/// fail its batch, or take a sibling down with it, free execution would
/// be worth provoking. Nothing a body can express reaches this, which is
/// why the fabrication here goes through the primitive fixtures use to
/// stand in for a kernel defect.
#[test]
fn a_transaction_that_lost_value_aborts_beside_one_that_did_not() {
    let honest = cell(0xB);
    let fabricating = cell(0xD);
    let batch = vec![
        BatchTx::new(tx(0x01), moving(point(honest, Mode::Delta)), env()),
        BatchTx::new(tx(0x02), moving(point(fabricating, Mode::Delta)), env()),
    ];
    let run = |entry: &BatchTx, mut session: KernelSession| {
        if entry.tx == tx(0x01) {
            session.grant_issuance(RESOURCE, ResourceKind::Fungible);
            let minted = session.mint(ISSUER_REP, 500).unwrap();
            session.cell_put(0, minted).unwrap();
        } else {
            // A credit with no mint behind it and no bucket to fund it.
            session.delta_add(0, 500).unwrap();
        }
        RunResult::Completed {
            session,
            answers: vec![],
            fuel: FUEL,
        }
    };

    for mode in [ExecutionMode::Serial, ExecutionMode::Parallel] {
        let outcome = execute_batch(
            Arc::new(MemoryStore::new()),
            &batch,
            &run,
            test_hash,
            mode,
            &Locality::All,
        )
        .expect("one transaction's loss is not the batch's failure");

        assert!(matches!(
            outcome.receipts[&tx(0x01)].outcome,
            Outcome::Completed { .. }
        ));
        assert_eq!(amount_at(&outcome.store, honest), 500, "the mint landed");

        assert_eq!(
            outcome.receipts[&tx(0x02)].outcome,
            Outcome::ProtocolError {
                reason: AbortReason::ValueNotConserved,
            },
        );
        assert_eq!(
            amount_at(&outcome.store, fabricating),
            0,
            "and nothing it credited survives"
        );
    }
}
