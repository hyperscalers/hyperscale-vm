//! The batch executor over generated batches.
//!
//! The hand fixture pins the semantics of one six-transaction batch; this
//! explores the shape space around it. Every generated batch is executed
//! three ways — serially, in parallel, and from a permuted input order —
//! and all three must agree on **everything the batch produces**: receipts,
//! point cells, collection entries, and the reservations still held when it
//! ends. Comparing cells alone would miss exactly the seams where ordering
//! and locality decisions live.
//!
//! Locality is generated beside the batch rather than pinned at
//! `Locality::All`. A shard owning an arbitrary subset of the key space
//! judges, folds, settles, and applies only its own keys, and every
//! property here holds for it too. Two of them are about locality itself:
//! a receipt carries its own transaction's movements and no predecessor's,
//! and a commutative leg derives the same receipt wherever it runs — the
//! property `executor_locality` proves by hand for one transfer.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, Hash32, Hasher, SlotId, TestHasher, child_key};
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, Capability, EnvInputs, ExecutionMode, KernelSession, Locality,
    MemoryStore, RunResult, WorkingStore, decode_amount, execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, CollectionId, Denomination, Effect, EffectSet,
    EffectTarget, EntryKey, Mode, Movement, Outcome, Presence, ResourceAddr, SubstateKey, TxHash,
    encode_amount,
};

/// What every cell these fixtures move value through holds.
const RESOURCE: Denomination = Denomination::Resource(ResourceAddr::new([0xE1; 31]));

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
use proptest::collection::vec as prop_vec;
use proptest::prelude::{Strategy, any, prop_oneof, proptest};

/// A small key space, so generated transactions actually collide.
const CELLS: u8 = 5;
/// The first byte of a cell's owner; `cell(index)` sits at `CELL_BASE + index`.
const CELL_BASE: u8 = 0xC0;
/// A separate space of permanently locked cells. A locked read only admits a
/// locked target, so generated locked-read claims land here — on keys nothing
/// can mutate, which is what the mode means.
const LOCKED_BASE: u8 = 0xD0;
const LOCKED_CELLS: u8 = 2;
const BOOK: Address = Address::new([0xB0; 31], AddressClass::Component);
const ASKS: CollectionId = CollectionId([4; 16]);
const FUNDING: u128 = 1_000;
/// The most transactions a generated batch carries.
const MAX_TXS: usize = 6;
/// The most claims one generated transaction carries.
const MAX_CLAIMS: usize = 4;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn cell(index: u8) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([CELL_BASE + index; 31], AddressClass::Component),
        SlotId(1),
        &[],
    )
}

fn locked_cell(index: u8) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new(
            [LOCKED_BASE + (index % LOCKED_CELLS); 31],
            AddressClass::Component,
        ),
        SlotId(1),
        &[],
    )
}

/// A shard owning exactly the cells `owned` flags, and the order book when
/// `book` is set.
fn shard_owning(owned: &[bool], book: bool) -> Locality {
    let owned = owned.to_vec();
    Locality::Owned(Arc::new(move |owner: Address| {
        if owner == BOOK {
            return book;
        }
        let index = owner.to_bytes()[0].wrapping_sub(CELL_BASE);
        owned.get(index as usize).copied().unwrap_or(false)
    }))
}

/// One declared access, as generated.
#[derive(Clone, Copy, Debug)]
enum Claim {
    Read(u8),
    Locked(u8),
    Delta(u8),
    Reserve(u8, u128),
    Write(u8),
    Interval { lo: u128, hi: u128, write: bool },
}

fn arb_claim() -> impl Strategy<Value = Claim> {
    prop_oneof![
        (0u8..CELLS).prop_map(Claim::Read),
        (0u8..CELLS).prop_map(Claim::Locked),
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
    (prop_vec(arb_claim(), 0..MAX_CLAIMS), any::<bool>())
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
            Claim::Locked(k) => Effect {
                target: EffectTarget::Point(locked_cell(k)),
                mode: Mode::Locked,
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
                    mode: Mode::Write {
                        requires: Presence::Either,
                    },
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
                mode: if write {
                    Mode::Write {
                        requires: Presence::Either,
                    }
                } else {
                    Mode::Read
                },
            },
        };
        set.insert(effect)
            .expect("amounts stay well under the fold");
    }
    set
}

/// A batch and the transactions whose guests trap, from generated specs.
fn batch_of(specs: &[TxSpec]) -> (Vec<BatchTx>, BTreeSet<TxHash>) {
    let identity = |index: usize| tx(u8::try_from(index).expect("small batch"));
    let aborting = specs
        .iter()
        .enumerate()
        .filter(|(_, spec)| spec.aborts)
        .map(|(index, _)| identity(index))
        .collect();
    let batch = specs
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            BatchTx::new(
                identity(index),
                moving(declared_of(spec)),
                EnvInputs {
                    clock_ms: 1_000,
                    randomness: [7; 32],
                },
            )
        })
        .collect();
    (batch, aborting)
}

/// The scripted guest: exercise every capability the session hands over,
/// deterministically in the transaction's own identity.
fn runner(aborting: BTreeSet<TxHash>) -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
    move |entry: &BatchTx, mut session: KernelSession| {
        let id = entry.tx;
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let seed = u128::from(id.0.0[0]);
        for (rep, capability) in caps.iter().enumerate() {
            let rep = u32::try_from(rep).expect("small table");
            match capability {
                Capability::Read(_) => {
                    let _ = session.read_cell(rep);
                }
                Capability::Locked(_) => {
                    let _ = session.locked_cell(rep);
                }
                Capability::Write(_) => {
                    let _ = session.write_cell_set(rep, vec![id.0.0[0]]);
                }
                // A value cell takes no bytes; what it takes is a debit.
                Capability::Amount(_) => {
                    let _ = session.write_take(rep, seed % 11);
                }
                // And a read of one answers a quantity, not bytes.
                Capability::AmountRead(_) => {
                    let _ = session.amount_cell_balance(rep);
                }
                Capability::InstanceRange(..) => {
                    let _ = session.range_count(rep);
                }
                Capability::Delta(_) => {
                    // Credit, then a smaller debit, so the cell moves both
                    // ways without always draining.
                    let _ = session.delta_add(rep, seed % 40);
                    let _ = session.delta_sub(rep, seed % 17);
                }
                Capability::Reserve { .. } => {
                    let _ = session.reserve_amount(rep);
                }
                Capability::RangeWrite(interval) => {
                    let order = interval.lo + (seed % (interval.hi - interval.lo + 1));
                    let _ = session.range_insert(rep, order, vec![id.0.0[0]]);
                    let count = session.range_count(rep).unwrap_or(0);
                    if count > 2 {
                        let _ = session.range_remove(rep, count - 1);
                    }
                }
                Capability::RangeRead(..) => {
                    let count = session.range_count(rep).unwrap_or(0);
                    for index in 0..count {
                        let _ = session.range_entry(rep, index);
                    }
                }
            }
        }
        // What an engine does after every call that can reach a scan.
        // Nothing here meters fuel, so the debt is settled rather than
        // charged — but it is settled, because the session refuses to
        // finish owing for a page somebody read.
        let _ = session.take_scan_debt();
        let outcome = if aborting.contains(&id) {
            Outcome::UserError {
                reason: AbortReason::Unreachable,
            }
        } else {
            Outcome::Completed { value: None }
        };
        let fuel = 3 + u64::from(id.0.0[0]);
        match outcome {
            Outcome::Completed { value } => RunResult::Completed {
                session,
                value,
                fuel,
            },
            outcome => RunResult::Aborted {
                session,
                outcome,
                fuel,
            },
        }
    }
}

/// The movements [`runner`] queues for one transaction: one per declared
/// delta cell, at the amounts it derives from the transaction's identity.
fn own_movements(entry: &BatchTx) -> BTreeMap<SubstateKey, Movement> {
    let seed = u128::from(entry.tx.0.0[0]);
    entry
        .declaration
        .set
        .iter()
        .filter_map(|effect| match effect {
            Effect {
                target: EffectTarget::Point(key),
                mode: Mode::Delta,
            } => Some((
                key,
                Movement {
                    credit: seed % 40,
                    debit: seed % 17,
                },
            )),
            _ => None,
        })
        .collect()
}

fn funded() -> MemoryStore {
    let mut store = MemoryStore::new();
    for index in 0..CELLS {
        store
            .write(cell(index), encode_amount(FUNDING).to_vec())
            .unwrap();
    }
    for index in 0..LOCKED_CELLS {
        store
            .write(locked_cell(index), encode_amount(FUNDING).to_vec())
            .unwrap();
        store.lock(locked_cell(index));
    }
    for order in 0..4u128 {
        store
            .entry_write(BOOK, ASKS, order, vec![u8::try_from(order).unwrap()])
            .unwrap();
    }
    store
}

/// Everything a batch leaves behind, in a comparable shape.
#[derive(Debug, PartialEq, Eq)]
struct EndState {
    cells: BTreeMap<SubstateKey, Vec<u8>>,
    entries: BTreeMap<EntryKey, Vec<u8>>,
    holds: BTreeMap<(SubstateKey, TxHash), u128>,
}

fn end_state(outcome: &BatchOutcome, batch: &[BatchTx]) -> EndState {
    // Every property batch executes over `funded()`, so the collapse
    // target is rebuilt rather than threaded through.
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
    let collapsed = outcome.store.collapse_onto(funded());
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

fn run(
    batch: &[BatchTx],
    mode: ExecutionMode,
    aborting: &BTreeSet<TxHash>,
    locality: &Locality,
) -> BatchOutcome {
    execute_batch(
        Arc::new(funded()),
        batch,
        &runner(aborting.clone()),
        test_hash,
        mode,
        locality,
    )
    .expect("a well-formed batch never fails as a batch")
}

/// One declared access of a cross-shard leg. Commutative modes only: a
/// fresh read of a cell resolves against state the owning shard has moved
/// and the counterpart has not, so a leg that takes one is not portable by
/// construction. A locked read is, because its target cannot differ between
/// sides carry.
#[derive(Clone, Copy, Debug)]
enum PortableClaim {
    Locked(u8),
    Delta(u8),
    Reserve(u8, u128),
}

/// The most one portable transaction may reserve per claim, so no cell's
/// declared demand can outrun its funding: an infeasible reservation is
/// judged only at the owning shard, and diverges by design.
const PORTABLE_RESERVE: u128 = FUNDING / (MAX_CLAIMS * MAX_TXS) as u128;

fn arb_portable_claim() -> impl Strategy<Value = PortableClaim> {
    prop_oneof![
        (0u8..CELLS).prop_map(PortableClaim::Locked),
        (0u8..CELLS).prop_map(PortableClaim::Delta),
        (0u8..CELLS, 0u128..PORTABLE_RESERVE).prop_map(|(k, a)| PortableClaim::Reserve(k, a)),
    ]
}

fn portable_declared(claims: &[PortableClaim]) -> EffectSet {
    let mut set = EffectSet::new();
    for claim in claims {
        let effect = match *claim {
            PortableClaim::Locked(k) => Effect {
                target: EffectTarget::Point(locked_cell(k)),
                mode: Mode::Locked,
            },
            PortableClaim::Delta(k) => Effect {
                target: EffectTarget::Point(cell(k)),
                mode: Mode::Delta,
            },
            PortableClaim::Reserve(k, amount) => Effect {
                target: EffectTarget::Point(cell(k)),
                mode: Mode::Reserve { amount },
            },
        };
        set.insert(effect).expect("bounded reserve amounts");
    }
    set
}

/// The portable guest: commutative capabilities only, with a net credit on
/// every cell it moves — an uncovered debit is judged at the owning shard
/// alone. What it reads reaches the receipt through the return value,
/// so a pinned read that disagreed between shards would show.
fn portable_runner() -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
    move |entry: &BatchTx, mut session: KernelSession| {
        let id = entry.tx;
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let seed = u128::from(id.0.0[0]);
        let mut observed = 0u64;
        for (rep, capability) in caps.iter().enumerate() {
            let rep = u32::try_from(rep).expect("small table");
            match capability {
                Capability::Locked(_) => {
                    let cell = session.locked_cell(rep).unwrap_or_default();
                    observed =
                        observed.wrapping_add(u64::from(cell.first().copied().unwrap_or_default()));
                }
                Capability::Delta(_) => {
                    let _ = session.delta_add(rep, seed % 40 + 17);
                    let _ = session.delta_sub(rep, seed % 17);
                }
                Capability::Reserve { .. } => {
                    let amount = session.reserve_amount(rep).unwrap_or_default();
                    observed = observed.wrapping_add(u64::from(amount.to_le_bytes()[0]));
                }
                _ => {}
            }
        }
        RunResult::Completed {
            session,
            value: Some(observed),
            fuel: 3 + u64::from(id.0.0[0]),
        }
    }
}

/// The reader in [`a_shard_that_owns_nothing_folds_nothing`], canonically
/// last so it stands downstream of every fold in its group.
const READER: TxHash = tx(0xFF);

/// The outbound guest: a delta capability takes the debit its transaction
/// was given — which may be more than the cell holds, because a shard that
/// owns nothing judges nothing — and a read capability reports what it
/// finds, so the baseline reaches the receipt.
fn outbound_runner(
    debits: BTreeMap<TxHash, (SubstateKey, u128)>,
) -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
    move |entry: &BatchTx, mut session: KernelSession| {
        let id = entry.tx;
        let caps: Vec<Capability> = session.capabilities().to_vec();
        let mut observed = 0u64;
        for (rep, capability) in caps.iter().enumerate() {
            let rep = u32::try_from(rep).expect("small table");
            match capability {
                Capability::Delta(_) => {
                    let debit = debits.get(&id).map_or(0, |(_, debit)| *debit);
                    let _ = session.delta_sub(rep, debit);
                }
                Capability::Read(_) => {
                    let cell = session.read_cell(rep).unwrap_or_default();
                    let amount = if cell.is_empty() {
                        0
                    } else {
                        decode_amount(&cell).unwrap_or_default()
                    };
                    observed = observed.wrapping_add(u64::try_from(amount).unwrap_or(u64::MAX));
                }
                _ => {}
            }
        }
        RunResult::Completed {
            session,
            value: Some(observed),
            fuel: 1,
        }
    }
}

proptest! {
    /// A shard that owns nothing folds nothing.
    ///
    /// Every movement is then an outbound record, belonging in the receipt
    /// and nowhere else. A fold that reached the overlay would show twice:
    /// in what a later member of the conflict group reads, and — when the
    /// cell could not carry the fold at all — in the movements that member
    /// goes on to report as its own.
    #[test]
    fn a_shard_that_owns_nothing_folds_nothing(
        debits in prop_vec(0u128..2 * FUNDING, 1..MAX_TXS),
    ) {
        let mut moved: BTreeMap<TxHash, (SubstateKey, u128)> = BTreeMap::new();
        let mut batch: Vec<BatchTx> = Vec::new();
        for (index, debit) in debits.iter().enumerate() {
            let index = u8::try_from(index).expect("small batch");
            let key = cell(index % CELLS);
            moved.insert(tx(index), (key, *debit));
            let mut declared = EffectSet::new();
            declared
                .insert(Effect {
                    target: EffectTarget::Point(key),
                    mode: Mode::Delta,
                })
                .expect("one mode per key");
            batch.push(BatchTx::new(tx(index), moving(declared), EnvInputs { clock_ms: 1_000, randomness: [7; 32] }));
        }
        // Reading every cell conflicts with every delta over one, so the
        // whole batch lands in a single conflict group.
        let mut reading = EffectSet::new();
        for index in 0..CELLS {
            reading
                .insert(Effect {
                    target: EffectTarget::Point(cell(index)),
                    mode: Mode::Read,
                })
                .expect("one mode per key");
        }
        batch.push(BatchTx::new(READER, moving(reading), EnvInputs { clock_ms: 1_000, randomness: [7; 32] }));

        let outcome = execute_batch(
            Arc::new(funded()),
            &batch,
            &outbound_runner(moved.clone()),
            test_hash,
            ExecutionMode::Serial,
            &shard_owning(&[false; CELLS as usize], false),
        )
        .expect("an outbound-only batch never fails as a batch");

        for entry in &batch {
            let expected = moved
                .get(&entry.tx)
                .map(|(key, debit)| {
                    (*key, Movement { credit: 0, debit: *debit })
                })
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            assert_eq!(
                outcome.receipts[&entry.tx].delta.movements,
                expected.into(),
                "{:?} carries movements it did not queue", entry.tx
            );
        }
        assert_eq!(
            outcome.receipts[&READER].outcome,
            Outcome::Completed {
                value: Some(u64::try_from(FUNDING).expect("fits") * u64::from(CELLS)),
            },
            "the reader saw a cell this shard does not own move"
        );
    }

    /// Schedule and input order cannot influence anything the batch
    /// produces, and a shard applies nothing outside the keys it owns.
    #[test]
    fn every_schedule_agrees_on_receipts_cells_entries_and_holds(
        specs in prop_vec(arb_tx(), 1..MAX_TXS + 1),
        owned in prop_vec(any::<bool>(), CELLS as usize),
        book in any::<bool>(),
    ) {
        let (batch, aborting) = batch_of(&specs);
        let locality = shard_owning(&owned, book);

        let serial = run(&batch, ExecutionMode::Serial, &aborting, &locality);
        let parallel = run(&batch, ExecutionMode::Parallel, &aborting, &locality);
        let mut reversed = batch.clone();
        reversed.reverse();
        let permuted = run(&reversed, ExecutionMode::Parallel, &aborting, &locality);

        assert_eq!(serial.receipts, parallel.receipts, "parallel receipts");
        assert_eq!(serial.receipts, permuted.receipts, "permuted receipts");
        let expected = end_state(&serial, &batch);
        assert_eq!(end_state(&parallel, &batch), expected, "parallel end state");
        assert_eq!(end_state(&permuted, &batch), expected, "permuted end state");

        // Funding seeds every cell, so a cell a shard does not own must
        // come back exactly as it was: its movements, writes, and settles
        // all belong to the owner.
        let mut store = serial.store;
        for index in 0..CELLS {
            if locality.is_local(Address::new([CELL_BASE + index; 31], AddressClass::Component)) {
                continue;
            }
            assert_eq!(
                store.read(cell(index)).unwrap(),
                Some(encode_amount(FUNDING).to_vec()),
                "cell {index} moved on a shard that does not own it"
            );
        }
    }

    /// A receipt's movements are its own transaction's. A conflict group
    /// threads committed state between its members, never a queued delta:
    /// a receipt that inherited one would stop being a function of the
    /// transaction that signed it.
    #[test]
    fn a_receipt_carries_only_its_own_movements(
        specs in prop_vec(arb_tx(), 1..MAX_TXS + 1),
        owned in prop_vec(any::<bool>(), CELLS as usize),
        book in any::<bool>(),
    ) {
        let (batch, aborting) = batch_of(&specs);
        let locality = shard_owning(&owned, book);
        let outcome = run(&batch, ExecutionMode::Parallel, &aborting, &locality);

        for entry in &batch {
            let receipt = &outcome.receipts[&entry.tx];
            // Only a completed transaction records anything; every abort
            // reports an empty delta whatever it queued.
            let expected = if matches!(receipt.outcome, Outcome::Completed { .. }) {
                own_movements(entry)
            } else {
                BTreeMap::new()
            };
            assert_eq!(
                receipt.delta.movements,
                expected.into(),
                "{:?} carries movements it did not queue", entry.tx
            );
        }
    }

    /// Every shard derives one receipt for a commutative leg.
    ///
    /// The two shards partition the key space and share a baseline: a
    /// counterpart carries the committed values it must observe, provisioned
    /// or client-proven. What differs is which keys each one judges, folds,
    /// settles, and applies — and none of that may reach the receipt.
    #[test]
    fn every_shard_derives_one_receipt_for_a_portable_batch(
        specs in prop_vec(prop_vec(arb_portable_claim(), 0..MAX_CLAIMS), 1..MAX_TXS + 1),
        split in prop_vec(any::<bool>(), CELLS as usize),
        book in any::<bool>(),
    ) {
        let batch: Vec<BatchTx> = specs
            .iter()
            .enumerate()
            .map(|(index, claims)| {
                BatchTx::new(
                    tx(u8::try_from(index).expect("small batch")),
                    moving(portable_declared(claims)),
                    EnvInputs {
                        clock_ms: 1_000,
                        randomness: [7; 32],
                    },
                )
            })
            .collect();
        let complement: Vec<bool> = split.iter().map(|owned| !owned).collect();

        let derive = |locality: &Locality| {
            execute_batch(
                Arc::new(funded()),
                &batch,
                &portable_runner(),
                test_hash,
                ExecutionMode::Parallel,
                locality,
            )
            .expect("a portable batch never fails as a batch")
        };

        let left = derive(&shard_owning(&split, book));
        let right = derive(&shard_owning(&complement, !book));
        assert_eq!(left.receipts, right.receipts);
    }

    /// A batch resolves every reservation it takes: settled by a completed
    /// transaction, released by an aborted one, never left standing.
    #[test]
    fn no_reservation_outlives_its_batch(
        specs in prop_vec(arb_tx(), 1..MAX_TXS + 1),
        owned in prop_vec(any::<bool>(), CELLS as usize),
        book in any::<bool>(),
    ) {
        let (batch, aborting) = batch_of(&specs);
        let outcome = run(
            &batch,
            ExecutionMode::Parallel,
            &aborting,
            &shard_owning(&owned, book),
        );
        assert!(
            end_state(&outcome, &batch).holds.is_empty(),
            "a reservation outlived the batch that took it"
        );
    }

    /// Amount cells never go negative or exceed what funding and credits
    /// can account for: the floor holds under every generated shape.
    #[test]
    fn amount_cells_stay_within_their_ledger(
        specs in prop_vec(arb_tx(), 1..MAX_TXS + 1),
        owned in prop_vec(any::<bool>(), CELLS as usize),
        book in any::<bool>(),
    ) {
        let (batch, aborting) = batch_of(&specs);
        let outcome = run(
            &batch,
            ExecutionMode::Serial,
            &aborting,
            &shard_owning(&owned, book),
        );
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
