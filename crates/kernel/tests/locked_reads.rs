//! A locked read reads a locked substate, and only a locked substate.
//!
//! The mode buys a read with no coherence and no participant, which is
//! sound exactly where no version of the target differs. On an unlocked
//! cell it would not be: the owning shard pre-reads the cell and a shard
//! that merely reads it does not, and a snapshot makes no participant, so
//! nothing carries the owner's value to anyone else. Two participants of
//! one transaction would read one key and derive two receipts.
//!
//! The invariance corpus cannot pin this down — an abort is
//! schedule-invariant too, so a snapshot that always refused would satisfy
//! every property there. These are the direct statements.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId,
    SubstateKey, TestHasher, child_key,
};
use hyperscale_vm_kernel::{
    AbortReason, BatchTx, Capability, ExecutionMode, KernelSession, Locality, MemoryStore, Outcome,
    RunResult, TxHash, WorkingStore, decode_amount, encode_amount, execute_batch,
};

const CONFIG: u128 = 7;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn cell(byte: u8) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([byte; 31], AddressClass::Component),
        RoleId(1),
        &[],
    )
}

const LOCKED: u8 = 0xC1;
const MUTABLE: u8 = 0xC2;
const LEDGER: u8 = 0xC3;

fn declare(effects: &[(SubstateKey, Mode)]) -> EffectSet {
    let mut set = EffectSet::new();
    for (key, mode) in effects {
        set.insert(Effect {
            target: EffectTarget::Point(*key),
            mode: *mode,
        })
        .unwrap();
    }
    set
}

/// The scripted guest: copies whatever it can snapshot into its write cell,
/// so the value a snapshot answered is observable in the receipt.
fn scripted(_entry: &BatchTx, mut session: KernelSession) -> RunResult {
    let caps: Vec<Capability> = session.capabilities().to_vec();
    let find = |wanted: fn(&Capability) -> bool| {
        caps.iter()
            .position(&wanted)
            .and_then(|index| u32::try_from(index).ok())
    };
    let snapshot = find(|c| matches!(c, Capability::Locked(_)));
    let write = find(|c| matches!(c, Capability::Write(_)));
    if let (Some(snapshot), Some(write)) = (snapshot, write) {
        let seen = session.locked_cell(snapshot).unwrap();
        session.write_cell_set(write, seen).unwrap();
    }
    RunResult {
        session,
        outcome: Outcome::Completed { value: None },
        fuel: 1,
    }
}

/// One locked cell holding `CONFIG`, one unlocked cell holding the same.
fn store() -> MemoryStore {
    let mut store = MemoryStore::new();
    for byte in [LOCKED, MUTABLE] {
        store
            .write(cell(byte), encode_amount(CONFIG).to_vec())
            .unwrap();
    }
    store.lock(cell(LOCKED));
    store.clear_log();
    store
}

fn run(declared: EffectSet) -> Outcome {
    let batch = vec![BatchTx::new(tx(0x01), declared, 1_000, [1; 32])];
    let outcome = execute_batch(
        Arc::new(store()),
        &batch,
        &scripted,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    outcome.receipts[&tx(0x01)].outcome.clone()
}

/// The mode works on the target it is for.
#[test]
fn a_locked_read_of_a_locked_cell_reads_it() {
    let batch = vec![BatchTx::new(
        tx(0x01),
        declare(&[(cell(LOCKED), Mode::Locked), (cell(LEDGER), Mode::Write)]),
        1_000,
        [1; 32],
    )];
    let outcome = execute_batch(
        Arc::new(store()),
        &batch,
        &scripted,
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    let receipt = &outcome.receipts[&tx(0x01)];
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "a locked target admits the mode: {:?}",
        receipt.outcome
    );
    let copied = receipt
        .delta
        .cells
        .get(&cell(LEDGER))
        .expect("the guest copied what it read")
        .clone()
        .expect("a value, not a removal");
    assert_eq!(decode_amount(&copied).unwrap(), CONFIG);
}

/// And refuses the target it is not for.
///
/// Without this the declaration would buy a read of mutable state that
/// takes no lock, makes no participant, and carries no proof — and two
/// shards of one transaction would answer it differently.
#[test]
fn a_locked_read_of_an_unlocked_cell_refuses() {
    let outcome = run(declare(&[
        (cell(MUTABLE), Mode::Locked),
        (cell(LEDGER), Mode::Write),
    ]));
    assert!(
        matches!(
            outcome,
            Outcome::UserError {
                reason: AbortReason::LockedReadOfUnlocked
            }
        ),
        "an unlocked snapshot must refuse as such: {outcome:?}"
    );
}

/// The refusal is about the target, not about the declaration's shape: the
/// same transaction reading the same cell freshly is fine, because a fresh
/// read provisions and makes its owner a participant.
#[test]
fn a_fresh_read_of_the_same_cell_is_admitted() {
    let outcome = run(declare(&[
        (cell(MUTABLE), Mode::Read),
        (cell(LEDGER), Mode::Write),
    ]));
    assert!(
        matches!(outcome, Outcome::Completed { .. }),
        "mutable state is read with `Read`: {outcome:?}"
    );
}
