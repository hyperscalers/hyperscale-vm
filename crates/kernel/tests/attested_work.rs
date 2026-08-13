//! What a shard attests it did, and the one thing that must not reach it.
//!
//! `Work::units` is built for a consumer that hashes it and signs it, so it
//! has to be a function of committed content alone. Fuel is that on a
//! completed execution and is not on an aborted one: wasmtime never
//! flushes its in-register counter when a core trap unwinds, while
//! `vm-ref` charges every executed operator, so the same trap reports two
//! different numbers (`spike_trap_fuel` pins the pair). The rule that
//! keeps the scalar agreeable is that only a completed execution attests
//! its fuel.
//!
//! The lane injects that divergence rather than reproducing it — the two
//! runtimes' behaviour is already pinned, and what needs testing here is
//! that the kernel is indifferent to it. A runner reporting wildly
//! different fuel for the same aborting outcome stands in for the pair,
//! which also makes the property hold against whatever the engines do
//! next.
//!
//! The rest is R1's actual demand: an abort's work is not zero, because
//! the declaration behind it was admitted, routed, and locked in full
//! whichever way execution ended — and R2's, that work is this shard's
//! share while the receipt beside it stays everyone's.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, FOOTPRINT_WEIGHT, Hash32,
    Hasher, Mode, RoleId, SubintentHash, SubstateKey, TestHasher, child_key, effect_units,
    footprint, nullifier_key, work_units,
};
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, Capability, ExecutionMode, KernelSession, Locality, MemoryStore,
    Outcome, Receipt, RunResult, TxHash, Work, WorkingStore, encode_amount, execute_batch,
};

const PAYER_BYTE: u8 = 0xA1;
const RECIPIENT_BYTE: u8 = 0xC1;

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

fn owned_by(byte: u8) -> Locality {
    Locality::Owned(Arc::new(move |owner: Address| owner.to_bytes()[0] == byte))
}

/// A declaration whose footprint is unmistakably nonzero and unevenly
/// split: the reserve sits at the payer, the delta and a wide range at the
/// recipient.
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
    set.insert(Effect {
        target: EffectTarget::Range {
            owner: Address::new([RECIPIENT_BYTE; 31], AddressClass::Component),
            collection: CollectionId([4; 16]),
            lo: 0,
            hi: 1 << 40,
            cap: 8,
        },
        mode: Mode::Read,
    })
    .unwrap();
    set
}

/// A guest that completes without touching anything, reporting `fuel`.
fn quiet_guest(fuel: u64) -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
    move |_entry: &BatchTx, session| RunResult {
        session,
        outcome: Outcome::Completed { value: None },
        fuel,
    }
}

/// A guest that traps, reporting `fuel` — the number the two runtimes
/// disagree on.
fn trapping_guest(fuel: u64) -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
    move |_entry: &BatchTx, session| RunResult {
        session,
        outcome: Outcome::UserError {
            reason: "integer divide by zero".into(),
        },
        fuel,
    }
}

/// The transfer guest: moves the reserved amount into the delta cell, so
/// the transaction actually completes.
fn transfer_guest(_entry: &BatchTx, mut session: KernelSession) -> RunResult {
    let caps: Vec<Capability> = session.capabilities().to_vec();
    let reserve = caps.iter().enumerate().find_map(|(rep, c)| match c {
        Capability::Reserve { .. } => Some(u32::try_from(rep).unwrap()),
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
        fuel: 7,
    }
}

fn funded_store(amount: u128) -> Arc<MemoryStore> {
    let mut store = MemoryStore::default();
    store
        .write(cell(PAYER_BYTE), encode_amount(amount).to_vec())
        .unwrap();
    Arc::new(store)
}

fn run_batch<R>(
    store: Arc<MemoryStore>,
    batch: &[BatchTx],
    runner: &R,
    locality: &Locality,
) -> BatchOutcome
where
    R: Fn(&BatchTx, KernelSession) -> RunResult + Sync,
{
    execute_batch(
        store,
        batch,
        runner,
        test_hash,
        ExecutionMode::Serial,
        locality,
    )
    .expect("batch executes")
}

/// Runs one transaction and returns its receipt and its attested work.
fn run_one<R>(declared: EffectSet, runner: &R, locality: &Locality) -> (Receipt, Work)
where
    R: Fn(&BatchTx, KernelSession) -> RunResult + Sync,
{
    let batch = [BatchTx::new(tx(1), declared, 1_000, [1; 32])];
    let outcome = run_batch(funded_store(1_000), &batch, runner, locality);
    (
        outcome.receipts[&tx(1)].clone(),
        *outcome.work.get(&tx(1)).expect("every receipt is priced"),
    )
}

#[test]
fn a_trapped_transactions_work_survives_the_engines_disagreement() {
    // The load-bearing one. Two runners report the same aborting outcome
    // with the fuel the two runtimes would each report at a core trap:
    // wasmtime's unflushed zero, and the spec's honest count. The attested
    // scalar must be blind to the difference.
    let declared = transfer_declared(100);
    let (_, unflushed) = run_one(declared.clone(), &trapping_guest(0), &Locality::All);
    let (_, counted) = run_one(declared, &trapping_guest(5_000), &Locality::All);

    assert_eq!(
        unflushed.units, counted.units,
        "the fuel register's flush state reached the attested quantity"
    );
    assert_eq!(unflushed.footprint, counted.footprint);

    // And the divergence really was present: a lane that agreed because
    // both sides reported the same fuel would prove nothing.
    assert_ne!(
        unflushed.fuel, counted.fuel,
        "the fixture must actually diverge on fuel, or the lane is vacuous"
    );
}

#[test]
fn an_aborts_work_is_its_local_footprint_and_is_not_zero() {
    // R1's demand: the transaction declared, routed, and locked in full
    // before it trapped, and the quantity that prices that must not
    // collapse to nothing exactly when the sender's leg failed.
    let declared = transfer_declared(100);
    let expected = footprint(&declared);
    let (_, work) = run_one(declared, &trapping_guest(0), &Locality::All);

    assert_eq!(work.footprint, expected);
    assert_eq!(work.units, work_units(0, expected));
    assert_eq!(
        work.units,
        FOOTPRINT_WEIGHT.saturating_mul(expected),
        "an abort attests its declaration alone"
    );
    assert!(work.units > 0, "an aborted leg still did work");
}

#[test]
fn a_completed_transaction_attests_both_halves() {
    // The other side of the rule: fuel is exact on completion, so it is
    // priced. A completion and an abort of the same declaration differ by
    // exactly the fuel term.
    let declared = transfer_declared(100);
    let expected = footprint(&declared);

    let (receipt, completed) = run_one(declared.clone(), &transfer_guest, &Locality::All);
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));
    assert_eq!(
        completed.units,
        work_units(completed.fuel, expected),
        "a completed execution prices its fuel"
    );

    let (_, aborted) = run_one(declared, &trapping_guest(completed.fuel), &Locality::All);
    assert!(
        completed.units > aborted.units,
        "completing consumed fuel an abort did not attest"
    );
    assert_eq!(completed.footprint, aborted.footprint);
}

#[test]
fn one_receipt_two_shares() {
    // R2, and the reason work travels beside a receipt rather than on it.
    // The receipt is the outbound effect record: every participant derives
    // the same one, and `executor_locality` holds them to it. Work is the
    // opposite — this shard's share, and the two participants are meant to
    // disagree. A locality-scoped field inside the receipt would have made
    // one structure carry both claims.
    let declared = transfer_declared(100);
    let batch = [BatchTx::new(tx(1), declared.clone(), 1_000, [1; 32])];

    let payer = run_batch(
        funded_store(1_000),
        &batch,
        &transfer_guest,
        &owned_by(PAYER_BYTE),
    );
    let recipient = run_batch(
        Arc::new(MemoryStore::default()),
        &batch,
        &transfer_guest,
        &owned_by(RECIPIENT_BYTE),
    );

    assert_eq!(
        payer.receipts, recipient.receipts,
        "the receipt is the record both participants derive"
    );
    assert_ne!(
        payer.work, recipient.work,
        "the work is the share each participant claims"
    );

    let payer_work = payer.work[&tx(1)];
    let recipient_work = recipient.work[&tx(1)];
    assert!(payer_work.footprint > 0 && recipient_work.footprint > 0);
    assert_eq!(
        payer_work.footprint + recipient_work.footprint,
        footprint(&declared),
        "the shards' shares must partition the declaration"
    );
}

#[test]
fn a_range_is_charged_its_declared_width_through_the_locality_filter() {
    // The filter turns on a target's owner and leaves the target alone, so
    // the span survives it. A filter that rebuilt targets — as the delta
    // walks do, yielding entries rather than claims — would flatten a wide
    // range to a point and quietly under-price the loudest declaration
    // there is.
    let mut wide = EffectSet::new();
    let range = Effect {
        target: EffectTarget::Range {
            owner: Address::new([RECIPIENT_BYTE; 31], AddressClass::Component),
            collection: CollectionId([4; 16]),
            lo: 0,
            hi: u128::MAX,
            cap: 8,
        },
        mode: Mode::Write,
    };
    wide.insert(range).unwrap();

    let recipient_side = owned_by(RECIPIENT_BYTE);
    assert_eq!(recipient_side.footprint(&wide), effect_units(range));
    assert!(
        recipient_side.footprint(&wide)
            > effect_units(Effect {
                target: EffectTarget::Point(cell(RECIPIENT_BYTE)),
                mode: Mode::Write,
            }),
        "a full-space range must cost more than a point"
    );
}

#[test]
fn every_abort_path_out_of_the_batch_carries_a_footprint() {
    // The rule is only as good as its least-visited exit, and the abort
    // taxonomy leaves the executor by several. Each case below takes a
    // different one.
    let payer = cell(PAYER_BYTE);

    // A reserve past the committed balance: refused by the batch judge,
    // before any group runs.
    let (receipt, starved) = run_one(transfer_declared(10_000), &transfer_guest, &Locality::All);
    assert!(matches!(receipt.outcome, Outcome::Infeasible { .. }));
    assert!(starved.units > 0, "a lost race still declared");

    // A guest trap: the session is discarded after execution. The fuel
    // check is what keeps this case honest — a declaration that failed to
    // materialize would also land as a `UserError`, from a different exit
    // and with no guest run at all, and would test nothing here.
    let (receipt, trapped) = run_one(transfer_declared(100), &trapping_guest(11), &Locality::All);
    assert!(matches!(receipt.outcome, Outcome::UserError { .. }));
    assert_eq!(trapped.fuel, 11, "the guest must actually have run");
    assert!(trapped.units > 0);

    // A spent nullifier: aborted inside the group, before materialization.
    let subintent = SubintentHash(Hash32([9; 32]));
    let nullifier = nullifier_key(
        &TestHasher,
        Address::new([PAYER_BYTE; 31], AddressClass::Component),
        subintent,
    );
    let mut declared = transfer_declared(100);
    declared
        .insert(Effect {
            target: EffectTarget::Point(nullifier),
            mode: Mode::Write,
        })
        .unwrap();
    let mut store = MemoryStore::default();
    store.write(payer, encode_amount(1_000).to_vec()).unwrap();
    store.write(nullifier, vec![1]).unwrap();
    let batch =
        [BatchTx::new(tx(1), declared.clone(), 1_000, [1; 32]).with_nullifiers(vec![nullifier])];
    let outcome = run_batch(Arc::new(store), &batch, &transfer_guest, &Locality::All);
    let spent = &outcome.receipts[&tx(1)];
    let spent_work = outcome.work[&tx(1)];
    assert!(matches!(spent.outcome, Outcome::NullifierSpent { .. }));
    assert_eq!(spent_work.footprint, footprint(&declared));
    assert!(spent_work.units > 0, "a spent subintent still declared");
}

#[test]
fn a_completion_flipped_at_apply_drops_its_fuel_but_keeps_its_declaration() {
    // The easy miss. Two transactions each debit the same cell; both
    // complete in their own group, and the canonically later one loses its
    // floor at apply, where its receipt is rebuilt as infeasible. Pricing
    // runs after that rebuild, so the loser drops its fuel term without
    // anything having to notice the verdict changed — and keeps the
    // declaration it put through routing and locking regardless.
    let declared = transfer_declared(600);
    let batch = [
        BatchTx::new(tx(1), transfer_declared(600), 1_000, [1; 32]),
        BatchTx::new(tx(2), declared.clone(), 1_000, [1; 32]),
    ];
    let mut store = MemoryStore::default();
    store
        .write(cell(PAYER_BYTE), encode_amount(1_000).to_vec())
        .unwrap();
    let outcome = run_batch(Arc::new(store), &batch, &transfer_guest, &Locality::All);

    let loser = outcome
        .receipts
        .iter()
        .find(|(_, receipt)| matches!(receipt.outcome, Outcome::Infeasible { .. }))
        .map(|(tx, _)| *tx)
        .expect("one of the two must lose the cell");
    let work = outcome.work[&loser];
    assert_eq!(
        work.footprint,
        footprint(&declared),
        "the loser's declaration is unchanged by losing"
    );
    assert_eq!(
        work.units,
        work_units(0, work.footprint),
        "a flipped completion must not keep pricing its fuel"
    );
    assert!(work.units > 0);
}

#[test]
fn work_is_a_function_of_the_batch_alone() {
    // R4's shape, at the reach of an in-process lane: the same batch under
    // the two execution modes attests the same work. Whether groups run
    // serially or on their own threads is a scheduling choice, and a
    // quantity that moved with it could not be voted on.
    let batch = [
        BatchTx::new(tx(1), transfer_declared(100), 1_000, [1; 32]),
        BatchTx::new(tx(2), transfer_declared(50), 1_000, [1; 32]),
    ];
    let run = |mode| {
        execute_batch(
            funded_store(1_000),
            &batch,
            &quiet_guest(13),
            test_hash,
            mode,
            &Locality::All,
        )
        .expect("batch executes")
        .work
    };
    assert_eq!(run(ExecutionMode::Serial), run(ExecutionMode::Parallel));
}

#[test]
fn every_receipt_is_priced() {
    // The two maps are keyed together and must stay that way: a receipt
    // without a work entry is a shard reporting a transaction it did no
    // work for, and the consumer sums the map rather than the receipts.
    let batch = [
        BatchTx::new(tx(1), transfer_declared(100), 1_000, [1; 32]),
        BatchTx::new(tx(2), transfer_declared(10_000), 1_000, [1; 32]),
        BatchTx::new(tx(3), transfer_declared(50), 1_000, [1; 32]),
    ];
    let outcome = run_batch(funded_store(1_000), &batch, &transfer_guest, &Locality::All);
    assert_eq!(
        outcome.receipts.keys().collect::<Vec<_>>(),
        outcome.work.keys().collect::<Vec<_>>(),
    );
    assert!(outcome.work.values().all(|work| work.units > 0));
}
