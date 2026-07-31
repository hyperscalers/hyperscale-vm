//! The deterministic-parallel batch executor.
//!
//! Four phases, each deterministic: **judge** every declared reservation
//! against committed state in canonical transaction-hash order, aborting
//! the infeasible as declared; **group** the remaining transactions by the
//! conflict relation over their effect sets — conflicting transactions
//! share a group, compatible ones never do; **execute** groups
//! independently (each threads its own store, members in canonical order;
//! whether groups run serially, in parallel, or under adversarial worker
//! timing cannot influence any receipt, because cross-group interaction is
//! commutative by construction and snapshots pin to the batch baseline);
//! **apply** every receipt's operations to the committed store, one
//! transaction at a time in canonical order — absolute writes, movements
//! floored at outstanding reservations, settlements. An uncovered debit
//! aborts its transaction as infeasible, never the batch.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

use hyperscale_vm_effects::{Effect, EffectSet, EffectTarget, Mode, SubstateKey};

use crate::conflict::conflicts;
use crate::modes::{ModeError, TxHash};
use crate::overlay::OverlayStore;
use crate::session::{
    EnvInputs, FinishError, KernelSession, Locality, MaterializeError, Outcome, Receipt, StateDelta,
};
use crate::store::{Base, StoreError, SubstateStore};

/// One transaction of a batch: its identity and its routed effect set.
#[derive(Clone, Debug)]
pub struct BatchTx {
    /// The transaction's identity: the canonical ordering key.
    pub tx: TxHash,
    /// The transaction's declared effect set on this shard.
    pub declared: EffectSet,
    /// The nullifier keys of every subintent the transaction commits.
    /// Each must also be declared as an exclusive write in `declared`,
    /// which [`execute_batch`] enforces: the declaration is what puts
    /// racing committers of one subintent in a single conflict group,
    /// where the spent check sees the winner's write. An existing cell
    /// at any of them aborts the transaction before it runs; completing
    /// writes them all — once-only by creation conflict.
    pub nullifiers: Vec<SubstateKey>,
    /// The transaction's clock in milliseconds. Per transaction, not per
    /// batch: every replica executing this transaction must pass the same
    /// value, and one batch may mix transactions with different clocks.
    pub clock_ms: u64,
    /// The transaction's randomness draw, on the same terms as
    /// [`BatchTx::clock_ms`]. A guest can read it, so it can reach the
    /// receipt — and the two shards of a cross-shard transaction execute
    /// it in different batches of different composition, so anything
    /// derived from the batch or from the executing block would put them
    /// on different receipts. The draw anchors to the transaction, and
    /// every replica of it passes the same one.
    pub randomness: [u8; 32],
}

impl BatchTx {
    /// A transaction with no bound subintents.
    ///
    /// The environment inputs are arguments rather than defaults: a
    /// silently zeroed clock or draw is a wrong consensus input that
    /// nothing would catch.
    #[must_use]
    pub const fn new(tx: TxHash, declared: EffectSet, clock_ms: u64, randomness: [u8; 32]) -> Self {
        Self {
            tx,
            declared,
            nullifiers: Vec::new(),
            clock_ms,
            randomness,
        }
    }

    /// Bind the subintents this transaction commits. Each key must also be
    /// declared as an exclusive write.
    #[must_use]
    pub fn with_nullifiers(mut self, nullifiers: Vec<SubstateKey>) -> Self {
        self.nullifiers = nullifiers;
        self
    }
}

/// The engine seam: runs one transaction's guest against its session.
/// Implementations wrap an engine (or none at all, for kernel-level
/// tests); the executor owns everything else.
pub trait GuestRunner: Sync {
    /// Execute the transaction, returning the session, how it ended, and
    /// the fuel consumed.
    fn run(&self, tx: TxHash, session: KernelSession) -> RunResult;
}

impl<F> GuestRunner for F
where
    F: Fn(TxHash, KernelSession) -> RunResult + Sync,
{
    fn run(&self, tx: TxHash, session: KernelSession) -> RunResult {
        self(tx, session)
    }
}

/// What a [`GuestRunner`] produced.
#[derive(Debug)]
pub struct RunResult {
    /// The session back from the engine.
    pub session: KernelSession,
    /// How the guest ended: completed, or a user-error trap.
    pub outcome: Outcome,
    /// Fuel consumed: engine schedule plus boundary supplement.
    pub fuel: u64,
}

/// How the executor schedules groups. The choice cannot influence any
/// receipt or the final store — that is the schedule-invariance property
/// the differential lanes assert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    /// One group after another, on the calling thread.
    Serial,
    /// One thread per group.
    Parallel,
}

/// A batch-level failure: a kernel defect, never a per-transaction abort.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BatchError {
    /// Two batch entries with the same transaction hash.
    #[error("duplicate transaction {0:?}")]
    DuplicateTx(TxHash),
    /// A nullifier key the transaction's effect set does not declare as an
    /// exclusive write. Once-only safety rests on that declaration: it is
    /// what forces racing committers of one subintent into a single
    /// conflict group, where the spent check sees the winner's write.
    #[error("transaction {tx:?} commits an undeclared nullifier {key:?}")]
    UndeclaredNullifier {
        /// The offending transaction.
        tx: TxHash,
        /// The nullifier key missing from the declaration.
        key: SubstateKey,
    },
    /// A session refused to finish — an oracle violation or store failure.
    #[error("finishing {tx:?}")]
    Finish {
        /// The offending transaction.
        tx: TxHash,
        /// The failure.
        #[source]
        source: FinishError,
    },
    /// A store failure while applying receipts.
    #[error(transparent)]
    Apply(#[from] StoreError),
}

/// The executed batch: every receipt, canonically ordered, and the end
/// state.
#[derive(Debug)]
pub struct BatchOutcome {
    /// Per-transaction receipts, in canonical order.
    pub receipts: BTreeMap<TxHash, Receipt>,
    /// The end state: the given base untouched, with the batch's full
    /// delta in the overlay's committed layer.
    pub store: OverlayStore,
}

fn declared_reservations(declared: &EffectSet) -> Vec<(SubstateKey, u128)> {
    declared
        .iter()
        .filter_map(|effect| match effect {
            Effect {
                target: EffectTarget::Point(key),
                mode: Mode::Reserve { amount },
            } => Some((key, amount)),
            _ => None,
        })
        .collect()
}

fn effect_sets_conflict(a: &EffectSet, b: &EffectSet) -> bool {
    a.iter()
        .any(|left| b.iter().any(|right| conflicts(&left, &right)))
}

fn root(component: &mut [usize], mut index: usize) -> usize {
    while component[index] != index {
        component[index] = component[component[index]];
        index = component[index];
    }
    index
}

/// Conflict groups over the batch: connected components of the conflict
/// relation, each sorted canonically.
fn conflict_groups(batch: &[&BatchTx]) -> Vec<Vec<usize>> {
    let mut component: Vec<usize> = (0..batch.len()).collect();
    for i in 0..batch.len() {
        for j in (i + 1)..batch.len() {
            if effect_sets_conflict(&batch[i].declared, &batch[j].declared) {
                let (a, b) = (root(&mut component, i), root(&mut component, j));
                component[a.max(b)] = a.min(b);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..batch.len() {
        groups
            .entry(root(&mut component, index))
            .or_default()
            .push(index);
    }
    groups.into_values().collect()
}

fn abort_receipt(outcome: Outcome, fuel: u64) -> Receipt {
    Receipt {
        outcome,
        delta: StateDelta::default(),
        fuel,
    }
}

/// Execute one conflict group: members in canonical order, each threading
/// the group's store; a non-completed transaction leaves the store as it
/// found it.
fn run_group<R: GuestRunner>(
    judged: &Arc<OverlayStore>,
    batch: &[&BatchTx],
    group: &[usize],
    runner: &R,
    hash_fn: fn(&[u8]) -> [u8; 32],
    locality: &Locality,
) -> Result<Vec<(TxHash, Receipt)>, BatchError> {
    let mut receipts = Vec::with_capacity(group.len());
    let shared: Arc<dyn Base> = Arc::<OverlayStore>::clone(judged);
    let mut store = OverlayStore::new(shared);
    for &index in group {
        let entry = batch[index];
        // A spent nullifier aborts before execution: some earlier
        // transaction — this group, an earlier batch, or the signer's
        // own cancellation — already committed the subintent. Only the
        // signer's shard holds the cell; elsewhere the owning shard's
        // verdict arrives through the wave combine.
        if entry
            .nullifiers
            .iter()
            .any(|key| locality.is_local(key.owner) && store.cell(*key).is_some())
        {
            receipts.push((
                entry.tx,
                abort_receipt(
                    Outcome::UserError {
                        reason: "subintent nullifier spent".into(),
                    },
                    0,
                ),
            ));
            continue;
        }
        let before = store.clone();
        let env = EnvInputs {
            clock_ms: entry.clock_ms,
            randomness: entry.randomness,
        };
        let session =
            match KernelSession::materialize(store, &entry.declared, entry.tx, env, hash_fn) {
                Ok(session) => {
                    // The rollback clone must drop here: it keeps the threaded
                    // layer's Arc unshared, so finish merges it in place.
                    drop(before);
                    session.with_locality(locality.clone())
                }
                Err(MaterializeError::Infeasible { key, amount }) => {
                    // Adoption makes this unreachable for batch-judged
                    // reservations; kept as an honest per-transaction abort.
                    receipts.push((
                        entry.tx,
                        abort_receipt(Outcome::Infeasible { key, amount }, 0),
                    ));
                    store = before;
                    continue;
                }
                Err(defect) => {
                    receipts.push((
                        entry.tx,
                        abort_receipt(
                            Outcome::UserError {
                                reason: defect.to_string(),
                            },
                            0,
                        ),
                    ));
                    store = before;
                    continue;
                }
            };
        let result = runner.run(entry.tx, session);
        match result.outcome {
            Outcome::Completed { .. } => {
                let (mut receipt, mut threaded) = result
                    .session
                    .finish(result.outcome, result.fuel)
                    .map_err(|source| BatchError::Finish {
                        tx: entry.tx,
                        source,
                    })?;
                // Committing spends every subintent: the nullifier cell
                // records the consuming transaction. The write enters the
                // receipt wherever the transaction runs — the outbound
                // effect record, filtered at apply like every other
                // operation — and reaches the store only at the signer's
                // shard, which is where the spent check reads it.
                for key in &entry.nullifiers {
                    if locality.is_local(key.owner) {
                        threaded.write(*key, entry.tx.0.0.to_vec())?;
                    }
                    receipt
                        .delta
                        .cells
                        .insert(*key, Some(entry.tx.0.0.to_vec()));
                }
                store = threaded;
                receipts.push((entry.tx, receipt));
            }
            aborted => {
                // The guest failed: its partial writes never commit.
                store = result.session.discard();
                receipts.push((entry.tx, abort_receipt(aborted, result.fuel)));
            }
        }
    }
    Ok(receipts)
}

/// The reserve-target pre-screen: a reserve declared on an unusable
/// target — a locked substate, a malformed amount cell — is the sender's
/// declaration defect. It aborts its transaction here, so the judge sees
/// only sound requests and its own errors stay kernel defects.
fn screen_reserve_targets<'batch>(
    judged: &OverlayStore,
    ordered: Vec<&'batch BatchTx>,
    locality: &Locality,
    receipts: &mut BTreeMap<TxHash, Receipt>,
) -> Vec<&'batch BatchTx> {
    let mut sound: Vec<&BatchTx> = Vec::with_capacity(ordered.len());
    for entry in ordered {
        let defect = declared_reservations(&entry.declared)
            .into_iter()
            .filter(|(key, _)| locality.is_local(key.owner))
            .find_map(|(key, _)| judged.check_reserve_target(key).err());
        if let Some(error) = defect {
            receipts.insert(
                entry.tx,
                abort_receipt(
                    Outcome::UserError {
                        reason: error.to_string(),
                    },
                    0,
                ),
            );
        } else {
            sound.push(entry);
        }
    }
    sound
}

/// Execute a batch of transactions over committed state.
///
/// Input order is immaterial: the batch is judged, grouped, executed, and
/// applied in canonical transaction-hash order.
///
/// # Errors
///
/// Any [`BatchError`] — all are kernel-level defects; per-transaction
/// failures land in receipts, never here.
///
/// # Panics
///
/// Only if a runner panics — the panic propagates from its worker — or on
/// the kernel defect of a group overlay outliving its group.
pub fn execute_batch<R: GuestRunner>(
    base: Arc<dyn Base>,
    batch: &[BatchTx],
    runner: &R,
    hash_fn: fn(&[u8]) -> [u8; 32],
    mode: ExecutionMode,
    locality: &Locality,
) -> Result<BatchOutcome, BatchError> {
    let mut seen = std::collections::BTreeSet::new();
    for entry in batch {
        if !seen.insert(entry.tx) {
            return Err(BatchError::DuplicateTx(entry.tx));
        }
        for key in &entry.nullifiers {
            if !entry.declared.contains(&Effect {
                target: EffectTarget::Point(*key),
                mode: Mode::Write,
            }) {
                return Err(BatchError::UndeclaredNullifier {
                    tx: entry.tx,
                    key: *key,
                });
            }
        }
    }
    let mut ordered: Vec<&BatchTx> = batch.iter().collect();
    ordered.sort_by_key(|entry| entry.tx);
    let mut receipts: BTreeMap<TxHash, Receipt> = BTreeMap::new();

    let mut judged = OverlayStore::new(base);
    let sound = screen_reserve_targets(&judged, ordered, locality, &mut receipts);

    // Judge every locally owned reservation in canonical order; hold the
    // feasible, abort the infeasible. Remote reservations are held at
    // their declared amounts without judging — the owning shard judges.
    let mut requests = Vec::new();
    for entry in &sound {
        for (key, amount) in declared_reservations(&entry.declared) {
            if locality.is_local(key.owner) {
                requests.push((entry.tx, key, amount));
            } else {
                judged.hold_unjudged(key, entry.tx, amount);
            }
        }
    }
    let verdicts = judged.judge_and_hold(&requests)?;
    let mut runnable: Vec<&BatchTx> = Vec::with_capacity(batch.len());
    for entry in sound {
        let refused = declared_reservations(&entry.declared)
            .into_iter()
            .find(|(key, _)| {
                verdicts
                    .get(&(entry.tx, *key))
                    .is_some_and(|verdict| !verdict.is_feasible())
            });
        if let Some((key, amount)) = refused {
            receipts.insert(
                entry.tx,
                abort_receipt(Outcome::Infeasible { key, amount }, 0),
            );
        } else {
            runnable.push(entry);
        }
    }
    judged.clear_log();
    judged.merge_active();

    // Group and execute; every group's overlay shares the judged store as
    // its immutable base.
    let judged = Arc::new(judged);
    let groups = conflict_groups(&runnable);
    let executed: Vec<Result<Vec<(TxHash, Receipt)>, BatchError>> = match mode {
        ExecutionMode::Serial => groups
            .iter()
            .map(|group| run_group(&judged, &runnable, group, runner, hash_fn, locality))
            .collect(),
        ExecutionMode::Parallel => thread::scope(|scope| {
            #[allow(clippy::needless_collect)] // spawn every worker before joining any
            let handles: Vec<_> = groups
                .iter()
                .map(|group| {
                    let judged = &judged;
                    let runnable = &runnable;
                    scope.spawn(move || {
                        run_group(judged, runnable, group, runner, hash_fn, locality)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("group worker never panics"))
                .collect()
        }),
    };
    for group_receipts in executed {
        for (tx, receipt) in group_receipts? {
            receipts.insert(tx, receipt);
        }
    }

    let mut store = Arc::try_unwrap(judged).expect("no group overlay outlives its group");
    apply_receipts(&mut store, batch, &mut receipts, locality)?;
    store.merge_active();

    Ok(BatchOutcome { receipts, store })
}

/// Canonical-order application, one transaction at a time: absolute writes
/// and entry changes, movements under the reservation floor, settles for
/// the completed, releases for the rest — all on locally owned keys only;
/// remote operations stay in the receipt as the outbound effect record. A
/// completed transaction whose local debit the floor no longer covers —
/// earlier transactions drained the cell — flips to an infeasible receipt
/// here, its fuel kept, its state never applied.
fn apply_receipts(
    store: &mut OverlayStore,
    batch: &[BatchTx],
    receipts: &mut BTreeMap<TxHash, Receipt>,
    locality: &Locality,
) -> Result<(), BatchError> {
    let order: Vec<TxHash> = receipts.keys().copied().collect();
    for tx in order {
        let receipt = receipts.get(&tx).expect("walked from keys");
        let mut refusal = None;
        if matches!(receipt.outcome, Outcome::Completed { .. }) {
            for (key, movement) in &receipt.delta.movements {
                if !locality.is_local(key.owner) {
                    continue;
                }
                match store.judge_movement(*key, movement.credit, movement.debit) {
                    Ok(_) => {}
                    Err(StoreError::Mode(ModeError::CellUnderflow | ModeError::CellOverflow)) => {
                        refusal = Some((*key, movement.debit));
                        break;
                    }
                    Err(defect) => return Err(defect.into()),
                }
            }
        }
        if matches!(receipt.outcome, Outcome::Completed { .. }) && refusal.is_none() {
            for (key, change) in &receipt.delta.cells {
                if !locality.is_local(key.owner) {
                    continue;
                }
                match change {
                    Some(value) => store.write(*key, value.clone())?,
                    None => {
                        store.remove(*key)?;
                    }
                }
            }
            for ((owner, collection, order), change) in &receipt.delta.entries {
                if !locality.is_local(*owner) {
                    continue;
                }
                match change {
                    Some(value) => store.entry_write(*owner, *collection, *order, value.clone())?,
                    None => {
                        store.entry_remove(*owner, *collection, *order)?;
                    }
                }
            }
            for (key, movement) in &receipt.delta.movements {
                if !locality.is_local(key.owner) {
                    continue;
                }
                store.apply_movement(*key, movement.credit, movement.debit)?;
            }
            for key in receipt.delta.settles.keys() {
                if !locality.is_local(key.owner) {
                    continue;
                }
                store.settle(*key, tx)?;
            }
            // A completed transaction's remote holds release here: the
            // settlement happened at the owning shard, not in this store.
            for entry in batch.iter().filter(|entry| entry.tx == tx) {
                for (key, _) in declared_reservations(&entry.declared) {
                    if !locality.is_local(key.owner) && store.held_reservation(key, tx).is_some() {
                        store.release(key, tx)?;
                    }
                }
            }
        } else {
            if let Some((key, amount)) = refusal {
                let fuel = receipt.fuel;
                receipts.insert(tx, abort_receipt(Outcome::Infeasible { key, amount }, fuel));
            }
            // Release whatever was held for an aborted transaction.
            for entry in batch.iter().filter(|entry| entry.tx == tx) {
                for (key, _) in declared_reservations(&entry.declared) {
                    if store.held_reservation(key, tx).is_some() {
                        store.release(key, tx)?;
                    }
                }
            }
        }
    }
    store.clear_log();
    Ok(())
}
