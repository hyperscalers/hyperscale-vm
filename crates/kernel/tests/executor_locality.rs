//! Cross-shard locality at the batch seams: each participant judges,
//! applies, and settles only the keys it owns; remote reservations are
//! held at their declared amounts without judging; and the covered
//! transfer's receipt is byte-identical on both sides — the outbound
//! effect record every participant derives. Nullifier writes follow the
//! same convention: in the receipt everywhere, in the store only where
//! the signer's shard reads them.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Declaration, Hash32, Hasher, IssuanceGrant, Issued, ResourceKind, SlotId, SubintentHash,
    TestHasher, child_key, nullifier_key,
};
use hyperscale_vm_kernel::{
    BatchTx, Capability, EnvInputs, ExecutionMode, KernelSession, Locality, MemoryStore, RunResult,
    WorkingStore, decode_amount, execute_batch,
};
use hyperscale_vm_types::{
    Address, AddressClass, Answer, Effect, EffectSet, EffectTarget, Mode, Movement, Moves, Outcome,
    ResourceAddr, SubstateKey, TxHash, encode_amount,
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
        matches!(effect.mode, Mode::Delta { .. } | Mode::Reserve { .. }).then_some(RESOURCE)
    })
}

const FUEL: u64 = 7;
const PAYER_BYTE: u8 = 0xA1;
const RECIPIENT_BYTE: u8 = 0xC1;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(1_000)
}

fn cell(byte: u8) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([byte; 31], AddressClass::Component),
        SlotId(1),
        &[],
    )
}

fn transfer_declared(amount: u128) -> EffectSet {
    let mut set = EffectSet::new();
    set.insert(Effect {
        target: EffectTarget::Point(cell(PAYER_BYTE)),
        mode: Mode::Reserve { amount },
    })
    .unwrap();
    set.insert(Effect {
        target: EffectTarget::Point(cell(RECIPIENT_BYTE)),
        mode: Mode::Delta { moves: Moves::Both },
    })
    .unwrap();
    set
}

/// The transfer guest: move the reserved amount into the delta cell.
fn transfer_guest(_entry: &BatchTx, mut session: KernelSession) -> RunResult {
    let caps: Vec<Capability> = session.capabilities().to_vec();
    let reserve = caps.iter().enumerate().find_map(|(rep, c)| match c {
        Capability::Reserve { .. } => Some(u32::try_from(rep).unwrap()),
        _ => None,
    });
    let delta = caps.iter().enumerate().find_map(|(rep, c)| match c {
        Capability::Delta { .. } => Some(u32::try_from(rep).unwrap()),
        _ => None,
    });
    if let (Some(reserve), Some(delta)) = (reserve, delta) {
        let funds = session.reserve_take(reserve, 0).unwrap();
        session.cell_put(delta, 0, funds).unwrap();
    }
    RunResult::Completed {
        session,
        answers: vec![],
        fuel: FUEL,
    }
}

fn owned_by(byte: u8) -> Locality {
    Locality::Owned(Arc::new(move |owner: Address| owner.to_bytes()[0] == byte))
}

#[test]
fn a_covered_transfer_derives_one_receipt_on_both_shards() {
    let batch = vec![BatchTx::new(
        TxHash(Hash32([0x11; 32])),
        moving(transfer_declared(50)),
        env(),
    )];

    // The payer's shard: it owns the reserve, judges it, settles it, and
    // leaves the recipient's credit unapplied — the outbound record.
    let mut payer_store = MemoryStore::new();
    payer_store.write(cell(PAYER_BYTE), encode_amount(100).to_vec());
    let payer = execute_batch(
        Arc::new(payer_store),
        &batch,
        &transfer_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(PAYER_BYTE),
    )
    .unwrap();

    // The recipient's shard: no payer cell exists here, yet the remote
    // reservation is held at its declared amount without judging, and
    // only the local credit applies.
    let recipient = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &transfer_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(RECIPIENT_BYTE),
    )
    .unwrap();

    // Both sides completed and derived the identical receipt.
    let tx = batch[0].tx;
    assert_eq!(payer.receipts, recipient.receipts);
    assert!(matches!(
        payer.receipts[&tx].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        payer.receipts[&tx]
            .delta
            .settles
            .get(&cell(PAYER_BYTE))
            .map(|movement| movement.debit),
        Some(50)
    );
    assert_eq!(
        payer.receipts[&tx]
            .delta
            .movements
            .get(&cell(RECIPIENT_BYTE))
            .unwrap()
            .credit,
        50
    );

    // Each store applied exactly its own keys.
    let mut payer_state = payer.store;
    assert_eq!(
        decode_amount(&payer_state.read(cell(PAYER_BYTE)).unwrap().unwrap()).unwrap(),
        50
    );
    assert_eq!(payer_state.read(cell(RECIPIENT_BYTE)).unwrap(), None);

    let mut recipient_state = recipient.store.clone();
    assert_eq!(
        decode_amount(&recipient_state.read(cell(RECIPIENT_BYTE)).unwrap().unwrap()).unwrap(),
        50
    );
    assert_eq!(recipient_state.read(cell(PAYER_BYTE)).unwrap(), None);
    // The unjudged remote hold released with the settlement elsewhere.
    assert_eq!(recipient.store.held_reservation(cell(PAYER_BYTE), tx), None);
}

/// The subintent's nullifier, under a signer the payer's shard owns.
fn signed_nullifier() -> SubstateKey {
    nullifier_key(
        &TestHasher,
        Address::new([PAYER_BYTE; 31], AddressClass::Component),
        SubintentHash(Hash32([0x99; 32])),
    )
}

/// A covered transfer that also commits one bound subintent.
fn committing_envelope(id: u8, amount: u128) -> BatchTx {
    let mut declared = transfer_declared(amount);
    declared
        .insert(Effect {
            target: EffectTarget::Point(signed_nullifier()),
            mode: Mode::Write { moves: Moves::Both },
        })
        .unwrap();
    BatchTx {
        tx: TxHash(Hash32([id; 32])),
        declaration: moving(declared),
        calls: Vec::new(),
        nullifiers: vec![signed_nullifier()],
        env: env(),
        gas_limit: u64::MAX,
    }
}

#[test]
fn a_committed_nullifier_reads_the_same_on_both_shards() {
    let batch = vec![committing_envelope(0x33, 50)];
    let tx = batch[0].tx;

    let mut payer_store = MemoryStore::new();
    payer_store.write(cell(PAYER_BYTE), encode_amount(100).to_vec());
    let payer = execute_batch(
        Arc::new(payer_store),
        &batch,
        &transfer_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(PAYER_BYTE),
    )
    .unwrap();

    let recipient = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &transfer_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(RECIPIENT_BYTE),
    )
    .unwrap();

    // The spend is in both receipts: it is the outbound effect record,
    // filtered at apply like a movement, never at the receipt.
    assert_eq!(payer.receipts, recipient.receipts);
    assert_eq!(
        payer.receipts[&tx].delta.cells.get(&signed_nullifier()),
        Some(&Some(tx.0.0.to_vec()))
    );

    // Only the signer's shard holds the cell.
    let mut payer_state = payer.store;
    assert_eq!(
        payer_state.read(signed_nullifier()).unwrap(),
        Some(tx.0.0.to_vec())
    );
    let mut recipient_state = recipient.store;
    assert_eq!(recipient_state.read(signed_nullifier()).unwrap(), None);
}

#[test]
fn an_environment_reading_guest_derives_one_receipt_on_both_shards() {
    // The two shards batch this transaction with different neighbours, so
    // an environment taken from the batch or from the executing block
    // would put them on different receipts. Anchored to the transaction,
    // it cannot.
    const EPOCH: u64 = 0x5A;
    let batch = vec![BatchTx::new(
        TxHash(Hash32([0x44; 32])),
        moving(transfer_declared(50)),
        EnvInputs {
            epoch: EPOCH,
            ..EnvInputs::unsealed(env().clock_ms)
        },
    )];
    let reading_guest = |_entry: &BatchTx, session: KernelSession| RunResult::Completed {
        answers: answered(session.epoch()),
        session,
        fuel: FUEL,
    };

    let mut payer_store = MemoryStore::new();
    payer_store.write(cell(PAYER_BYTE), encode_amount(100).to_vec());
    let payer = execute_batch(
        Arc::new(payer_store),
        &batch,
        &reading_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(PAYER_BYTE),
    )
    .unwrap();
    let recipient = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &reading_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(RECIPIENT_BYTE),
    )
    .unwrap();

    assert_eq!(payer.receipts, recipient.receipts);
    assert_eq!(
        payer.receipts[&batch[0].tx].outcome,
        Outcome::Completed {
            answers: answered(EPOCH)
        }
    );

    // And the environment is receipt-affecting, which is what makes
    // carrying it on the transaction load-bearing rather than tidy: hand
    // one shard a different one and the two stop agreeing.
    let divergent = vec![BatchTx::new(
        batch[0].tx,
        moving(transfer_declared(50)),
        EnvInputs::unsealed(env().clock_ms),
    )];
    let elsewhere = execute_batch(
        Arc::new(MemoryStore::new()),
        &divergent,
        &reading_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(RECIPIENT_BYTE),
    )
    .unwrap();
    assert_ne!(payer.receipts, elsewhere.receipts);
}

/// A guest driving whatever it is handed: a delta capability takes
/// `credit` then `debit`, and a read capability reports what the cell
/// holds — an absent cell reading as zero, the normalisation every guest
/// applies.
fn moving_guest(credit: u128, debit: u128) -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
    move |_entry: &BatchTx, mut session: KernelSession| {
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let mut answers = Vec::new();
        for (rep, capability) in caps.iter().enumerate() {
            let rep = u32::try_from(rep).unwrap();
            match capability {
                Capability::Delta { .. } => {
                    // Both ways through the bucket, minting behind the
                    // credit and burning after the debit, so the fixture
                    // moves value rather than conjuring it.
                    session.grant_issuance(vec![IssuanceGrant {
                        resource: RESOURCE,
                        kind: ResourceKind::Fungible,
                        direction: Issued::Either,
                    }]);
                    let minted = session.mint(0, credit).unwrap();
                    session.cell_put(rep, 0, minted).unwrap();
                    let taken = session.cell_take(rep, 0, debit).unwrap();
                    session.burn(taken).unwrap();
                }
                Capability::Read(_) => {
                    let cell = session.cell_get(rep, 0).unwrap();
                    let amount = if cell.is_empty() {
                        0
                    } else {
                        decode_amount(&cell).unwrap()
                    };
                    answers = answered(u64::try_from(amount).unwrap());
                }
                _ => {}
            }
        }
        RunResult::Completed {
            session,
            answers,
            fuel: FUEL,
        }
    }
}

/// One transaction declaring a movement on a remote cell, and a second
/// declaring only a read of it. Read conflicts with delta, so the two
/// share a conflict group and the second runs over what the first
/// threaded.
fn remote_movement_batch() -> Vec<BatchTx> {
    let mut read = EffectSet::new();
    read.insert(Effect {
        target: EffectTarget::Point(cell(PAYER_BYTE)),
        mode: Mode::Read,
    })
    .unwrap();
    let mut moved = EffectSet::new();
    moved
        .insert(Effect {
            target: EffectTarget::Point(cell(PAYER_BYTE)),
            mode: Mode::Delta { moves: Moves::Both },
        })
        .unwrap();
    vec![
        BatchTx::new(TxHash(Hash32([0x51; 32])), moving(moved), env()),
        BatchTx::new(TxHash(Hash32([0x52; 32])), moving(read), env()),
    ]
}

#[test]
fn a_remote_debit_never_reaches_the_next_receipt() {
    // The recipient's shard holds nothing of the payer's cell, so the
    // debit cannot fold here — the owning shard folds it, and the
    // movement is this shard's outbound record. What it must not do is
    // stay queued: the next member of the conflict group would build its
    // own movements from it and carry another transaction's debit into
    // its receipt.
    let batch = remote_movement_batch();
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &moving_guest(0, 100),
        test_hash,
        ExecutionMode::Serial,
        &owned_by(RECIPIENT_BYTE),
    )
    .unwrap();

    // The mover records the outbound movement...
    assert_eq!(
        outcome.receipts[&batch[0].tx]
            .delta
            .movements
            .get(&cell(PAYER_BYTE)),
        Some(&Movement {
            resource: RESOURCE,
            credit: 0,
            debit: 100,
        })
    );
    // ...and the reader records nothing at all.
    assert!(
        outcome.receipts[&batch[1].tx].delta.is_empty(),
        "the reader inherited {:?}",
        outcome.receipts[&batch[1].tx].delta
    );
}

#[test]
fn a_remote_credit_never_becomes_a_local_balance() {
    // The same blindness without any error involved: folding a remote
    // credit into the group's overlay would hand the next guest a balance
    // for a cell this shard does not own, and the owning shard's guest a
    // different one — two receipts for one transaction.
    let batch = remote_movement_batch();
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &moving_guest(50, 0),
        test_hash,
        ExecutionMode::Serial,
        &owned_by(RECIPIENT_BYTE),
    )
    .unwrap();

    assert_eq!(
        outcome.receipts[&batch[1].tx].outcome,
        Outcome::Completed {
            answers: answered(0)
        }
    );
    let mut state = outcome.store;
    assert_eq!(state.read(cell(PAYER_BYTE)).unwrap(), None);
}

#[test]
fn only_the_owning_shard_judges_an_uncovered_reserve() {
    let batch = vec![BatchTx::new(
        TxHash(Hash32([0x22; 32])),
        moving(transfer_declared(50)),
        env(),
    )];

    // The payer's shard sees the shortfall and refuses.
    let mut payer_store = MemoryStore::new();
    payer_store.write(cell(PAYER_BYTE), encode_amount(10).to_vec());
    let payer = execute_batch(
        Arc::new(payer_store),
        &batch,
        &transfer_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(PAYER_BYTE),
    )
    .unwrap();
    assert!(matches!(
        payer.receipts[&batch[0].tx].outcome,
        Outcome::Infeasible { .. }
    ));

    // The counterpart executes optimistically; the owning shard's
    // verdict reaches it through the tick combine, not this batch.
    let recipient = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &transfer_guest,
        test_hash,
        ExecutionMode::Serial,
        &owned_by(RECIPIENT_BYTE),
    )
    .unwrap();
    assert!(matches!(
        recipient.receipts[&batch[0].tx].outcome,
        Outcome::Completed { .. }
    ));
}
