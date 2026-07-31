//! Cross-shard locality at the batch seams: each participant judges,
//! applies, and settles only the keys it owns; remote reservations are
//! held at their declared amounts without judging; and the covered
//! transfer's receipt is byte-identical on both sides — the outbound
//! effect record every participant derives.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubstateKey,
    TestHasher, child_key,
};
use hyperscale_vm_kernel::{
    BatchTx, Capability, EnvInputs, ExecutionMode, KernelSession, Locality, MemoryStore, Outcome,
    RunResult, SubstateStore, TxHash, decode_amount, encode_amount, execute_batch,
};

const FUEL: u64 = 7;
const PAYER_BYTE: u8 = 0xA1;
const RECIPIENT_BYTE: u8 = 0xC1;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 1_000,
        randomness: [1; 32],
    }
}

fn cell(byte: u8) -> SubstateKey {
    child_key(&TestHasher, Address([byte; 16]), RoleId(1), &[])
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
        mode: Mode::Delta,
    })
    .unwrap();
    set
}

/// The transfer guest: move the reserved amount into the delta cell.
fn transfer_guest(_id: TxHash, mut session: KernelSession) -> RunResult {
    let caps: Vec<Capability> = session.capabilities().to_vec();
    let reserve = caps.iter().enumerate().find_map(|(rep, c)| match c {
        Capability::Reserve(_) => Some(u32::try_from(rep).unwrap()),
        _ => None,
    });
    let delta = caps.iter().enumerate().find_map(|(rep, c)| match c {
        Capability::Delta(_) => Some(u32::try_from(rep).unwrap()),
        _ => None,
    });
    if let (Some(reserve), Some(delta)) = (reserve, delta) {
        let amount = session.reserve_amount(reserve).unwrap();
        session.delta_add(delta, &amount).unwrap();
    }
    RunResult {
        session,
        outcome: Outcome::Completed { value: None },
        fuel: FUEL,
    }
}

fn owned_by(byte: u8) -> Locality {
    Locality::Owned(Arc::new(move |owner: Address| owner.0[0] == byte))
}

#[test]
fn a_covered_transfer_derives_one_receipt_on_both_shards() {
    let batch = vec![BatchTx::new(
        TxHash(Hash32([0x11; 32])),
        transfer_declared(50),
    )];

    // The payer's shard: it owns the reserve, judges it, settles it, and
    // leaves the recipient's credit unapplied — the outbound record.
    let mut payer_store = MemoryStore::new();
    payer_store
        .write(cell(PAYER_BYTE), encode_amount(100).to_vec())
        .unwrap();
    payer_store.clear_log();
    let payer = execute_batch(
        Arc::new(payer_store),
        &batch,
        &transfer_guest,
        env().randomness,
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
        env().randomness,
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
        payer.receipts[&tx].delta.settles.get(&cell(PAYER_BYTE)),
        Some(&50)
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

#[test]
fn only_the_owning_shard_judges_an_uncovered_reserve() {
    let batch = vec![BatchTx::new(
        TxHash(Hash32([0x22; 32])),
        transfer_declared(50),
    )];

    // The payer's shard sees the shortfall and refuses.
    let mut payer_store = MemoryStore::new();
    payer_store
        .write(cell(PAYER_BYTE), encode_amount(10).to_vec())
        .unwrap();
    payer_store.clear_log();
    let payer = execute_batch(
        Arc::new(payer_store),
        &batch,
        &transfer_guest,
        env().randomness,
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
    // verdict reaches it through the wave combine, not this batch.
    let recipient = execute_batch(
        Arc::new(MemoryStore::new()),
        &batch,
        &transfer_guest,
        env().randomness,
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
