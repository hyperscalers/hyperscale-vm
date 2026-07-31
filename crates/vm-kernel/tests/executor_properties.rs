//! The batch executor over generated batches.
//!
//! The hand fixture pins the semantics of one six-transaction batch; this
//! explores the shape space around it. Every generated batch is executed
//! three ways — serially, in parallel, and from a permuted input order —
//! and all three must agree on **everything the batch produces**: receipts,
//! point cells, collection entries, and the reservations still held when it
//! ends. Comparing cells alone would miss exactly the seams where ordering
//! and locality decisions live.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubstateKey,
    TestHasher, Window, child_key,
};
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, Capability, ExecutionMode, KernelSession, Locality, MemoryStore,
    Outcome, RunResult, SubstateStore, TxHash, decode_amount, encode_amount, execute_batch,
};
use proptest::collection::vec as prop_vec;
use proptest::prelude::{Strategy, any, prop_oneof, proptest};

/// A small key space, so generated transactions actually collide.
const CELLS: u8 = 5;
const BOOK: Address = Address([0xB0; 16]);
const ASKS: RoleId = RoleId(4);
const FUNDING: u128 = 1_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn cell(index: u8) -> SubstateKey {
    child_key(&TestHasher, Address([0xC0 + index; 16]), RoleId(1), &[])
}

/// One declared access, as generated.
#[derive(Clone, Copy, Debug)]
enum Claim {
    Read(u8),
    Snapshot(u8),
    Delta(u8),
    Reserve(u8, u128),
    Write(u8),
    Interval { lo: u128, hi: u128, write: bool },
}

fn arb_claim() -> impl Strategy<Value = Claim> {
    prop_oneof![
        (0u8..CELLS).prop_map(Claim::Read),
        (0u8..CELLS).prop_map(Claim::Snapshot),
        (0u8..CELLS).prop_map(Claim::Delta),
        (0u8..CELLS, 0u128..300).prop_map(|(k, a)| Claim::Reserve(k, a)),
        (0u8..CELLS).prop_map(Claim::Write),
        (0u128..8, 0u128..8, any::<bool>()).prop_map(|(a, b, write)| Claim::Interval {
            lo: a.min(b),
            hi: a.max(b),
            write,
        }),
    ]
}

/// One generated transaction: what it declares, and whether its guest
/// completes or traps.
#[derive(Clone, Debug)]
struct TxSpec {
    claims: Vec<Claim>,
    aborts: bool,
}

fn arb_tx() -> impl Strategy<Value = TxSpec> {
    (prop_vec(arb_claim(), 0..4), any::<bool>())
        .prop_map(|(claims, aborts)| TxSpec { claims, aborts })
}

/// Lower a spec to an effect set, dropping claims that would make the
/// transaction self-conflicting — one transaction cannot hold both an
/// exclusive and a commutative mode on one cell, and a batch entry that
/// does is a declaration defect rather than a scheduling question.
fn declared_of(spec: &TxSpec) -> EffectSet {
    let mut set = EffectSet::new();
    let mut exclusive: BTreeSet<u8> = BTreeSet::new();
    let mut commutative: BTreeSet<u8> = BTreeSet::new();
    for claim in &spec.claims {
        let effect = match *claim {
            Claim::Read(k) => Effect {
                target: EffectTarget::Point(cell(k)),
                mode: Mode::Read,
            },
            Claim::Snapshot(k) => Effect {
                target: EffectTarget::Point(cell(k)),
                mode: Mode::Snapshot {
                    window: Window::Bounded(4),
                },
            },
            Claim::Delta(k) => {
                if exclusive.contains(&k) {
                    continue;
                }
                commutative.insert(k);
                Effect {
                    target: EffectTarget::Point(cell(k)),
                    mode: Mode::Delta,
                }
            }
            Claim::Reserve(k, amount) => {
                if exclusive.contains(&k) {
                    continue;
                }
                commutative.insert(k);
                Effect {
                    target: EffectTarget::Point(cell(k)),
                    mode: Mode::Reserve { amount },
                }
            }
            Claim::Write(k) => {
                if commutative.contains(&k) {
                    continue;
                }
                exclusive.insert(k);
                Effect {
                    target: EffectTarget::Point(cell(k)),
                    mode: Mode::Write,
                }
            }
            Claim::Interval { lo, hi, write } => Effect {
                target: EffectTarget::Range {
                    owner: BOOK,
                    collection: ASKS,
                    lo,
                    hi,
                    cap: 8,
                },
                mode: if write { Mode::Write } else { Mode::Read },
            },
        };
        set.insert(effect)
            .expect("amounts stay well under the fold");
    }
    set
}

/// The scripted guest: exercise every capability the session hands over,
/// deterministically in the transaction's own identity.
fn runner(aborting: BTreeSet<TxHash>) -> impl Fn(TxHash, KernelSession) -> RunResult + Sync {
    move |id, mut session: KernelSession| {
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let seed = u128::from(id.0.0[0]);
        for (rep, capability) in caps.iter().enumerate() {
            let rep = u32::try_from(rep).expect("small table");
            match capability {
                Capability::Read(_) => {
                    let _ = session.read_cell(rep);
                }
                Capability::Snapshot(_) => {
                    let _ = session.snap_cell(rep);
                }
                Capability::Write(_) => {
                    let _ = session.write_cell_set(rep, vec![id.0.0[0]]);
                }
                Capability::Delta(_) => {
                    // Credit, then a smaller debit, so the cell moves both
                    // ways without always draining.
                    let _ = session.delta_add(rep, &encode_amount(seed % 40));
                    let _ = session.delta_sub(rep, &encode_amount(seed % 17));
                }
                Capability::Reserve(_) => {
                    let _ = session.reserve_amount(rep);
                }
                Capability::RangeWrite { lo, hi, .. } => {
                    let order = lo + (seed % (hi - lo + 1));
                    let _ = session.range_insert(rep, &encode_amount(order), vec![id.0.0[0]]);
                    let count = session.range_count(rep).unwrap_or(0);
                    if count > 2 {
                        let _ = session.range_remove(rep, count - 1);
                    }
                }
                Capability::RangeRead { .. } => {
                    let count = session.range_count(rep).unwrap_or(0);
                    for index in 0..count {
                        let _ = session.range_entry(rep, index);
                    }
                }
            }
        }
        let outcome = if aborting.contains(&id) {
            Outcome::UserError {
                reason: "scripted abort".into(),
            }
        } else {
            Outcome::Completed { value: None }
        };
        RunResult {
            session,
            outcome,
            fuel: 3 + u64::from(id.0.0[0]),
        }
    }
}

fn funded() -> MemoryStore {
    let mut store = MemoryStore::new();
    for index in 0..CELLS {
        store
            .write(cell(index), encode_amount(FUNDING).to_vec())
            .unwrap();
    }
    for order in 0..4u128 {
        store
            .entry_write(BOOK, ASKS, order, vec![u8::try_from(order).unwrap()])
            .unwrap();
    }
    store.clear_log();
    store
}

/// Everything a batch leaves behind, in a comparable shape.
#[derive(Debug, PartialEq, Eq)]
struct EndState {
    cells: BTreeMap<SubstateKey, Vec<u8>>,
    entries: BTreeMap<(Address, RoleId, u128), Vec<u8>>,
    holds: BTreeMap<(SubstateKey, TxHash), u128>,
}

fn end_state(outcome: &BatchOutcome, batch: &[BatchTx]) -> EndState {
    let holds = batch
        .iter()
        .flat_map(|entry| {
            (0..CELLS).filter_map(move |index| {
                outcome
                    .store
                    .held_reservation(cell(index), entry.tx)
                    .map(|amount| ((cell(index), entry.tx), amount))
            })
        })
        .collect();
    let collapsed = outcome.store.clone().collapse();
    EndState {
        cells: collapsed
            .cells()
            .map(|(key, value)| (key, value.to_vec()))
            .collect(),
        entries: collapsed
            .collection_entries()
            .map(|(key, value)| (key, value.to_vec()))
            .collect(),
        holds,
    }
}

fn run(batch: &[BatchTx], mode: ExecutionMode, aborting: &BTreeSet<TxHash>) -> BatchOutcome {
    execute_batch(
        Arc::new(funded()),
        batch,
        &runner(aborting.clone()),
        test_hash,
        mode,
        &Locality::All,
    )
    .expect("a well-formed batch never fails as a batch")
}

proptest! {
    /// Schedule and input order cannot influence anything the batch
    /// produces.
    #[test]
    fn every_schedule_agrees_on_receipts_cells_entries_and_holds(
        specs in prop_vec(arb_tx(), 1..7),
    ) {
        let aborting: BTreeSet<TxHash> = specs
            .iter()
            .enumerate()
            .filter(|(_, spec)| spec.aborts)
            .map(|(index, _)| tx(u8::try_from(index).expect("small batch")))
            .collect();
        let batch: Vec<BatchTx> = specs
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                BatchTx::new(
                    tx(u8::try_from(index).expect("small batch")),
                    declared_of(spec),
                    1_000,
                    [7; 32],
                )
            })
            .collect();

        let serial = run(&batch, ExecutionMode::Serial, &aborting);
        let parallel = run(&batch, ExecutionMode::Parallel, &aborting);
        let mut reversed = batch.clone();
        reversed.reverse();
        let permuted = run(&reversed, ExecutionMode::Parallel, &aborting);

        assert_eq!(serial.receipts, parallel.receipts, "parallel receipts");
        assert_eq!(serial.receipts, permuted.receipts, "permuted receipts");
        let expected = end_state(&serial, &batch);
        assert_eq!(end_state(&parallel, &batch), expected, "parallel end state");
        assert_eq!(end_state(&permuted, &batch), expected, "permuted end state");
    }

    /// A batch resolves every reservation it takes: settled by a completed
    /// transaction, released by an aborted one, never left standing.
    #[test]
    fn no_reservation_outlives_its_batch(specs in prop_vec(arb_tx(), 1..7)) {
        let aborting: BTreeSet<TxHash> = specs
            .iter()
            .enumerate()
            .filter(|(_, spec)| spec.aborts)
            .map(|(index, _)| tx(u8::try_from(index).expect("small batch")))
            .collect();
        let batch: Vec<BatchTx> = specs
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                BatchTx::new(
                    tx(u8::try_from(index).expect("small batch")),
                    declared_of(spec),
                    1_000,
                    [7; 32],
                )
            })
            .collect();

        let outcome = run(&batch, ExecutionMode::Parallel, &aborting);
        assert!(
            end_state(&outcome, &batch).holds.is_empty(),
            "a reservation outlived the batch that took it"
        );
    }

    /// Amount cells never go negative or exceed what funding and credits
    /// can account for: the floor holds under every generated shape.
    #[test]
    fn amount_cells_stay_within_their_ledger(specs in prop_vec(arb_tx(), 1..7)) {
        let aborting: BTreeSet<TxHash> = specs
            .iter()
            .enumerate()
            .filter(|(_, spec)| spec.aborts)
            .map(|(index, _)| tx(u8::try_from(index).expect("small batch")))
            .collect();
        let batch: Vec<BatchTx> = specs
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                BatchTx::new(
                    tx(u8::try_from(index).expect("small batch")),
                    declared_of(spec),
                    1_000,
                    [7; 32],
                )
            })
            .collect();

        let outcome = run(&batch, ExecutionMode::Serial, &aborting);
        let mut store = outcome.store;
        for index in 0..CELLS {
            // A write capability puts arbitrary bytes in a cell, so only
            // cells that stayed amount-shaped are ledger claims.
            if let Some(bytes) = store.read(cell(index)).unwrap()
                && let Ok(amount) = decode_amount(&bytes)
            {
                assert!(
                    amount <= FUNDING * u128::from(CELLS) + 10_000,
                    "cell {index} holds {amount}, past anything the batch could credit"
                );
            }
        }
    }
}
