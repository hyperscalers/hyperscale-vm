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
//! **apply** every receipt's operations to the committed store in
//! canonical order — absolute writes, movement folds, settlements.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

use hyperscale_vm_effects::{Effect, EffectSet, EffectTarget, Mode, SubstateKey};

use crate::conflict::conflicts;
use crate::modes::{DeltaOp, ModeError, TxHash};
use crate::overlay::OverlayStore;
use crate::session::{
    EnvInputs, FinishError, KernelSession, MaterializeError, Outcome, Receipt, StateDelta,
};
use crate::store::{MemoryStore, StoreError, SubstateStore};

/// One transaction of a batch: its identity and its routed effect set.
#[derive(Clone, Debug)]
pub struct BatchTx {
    /// The transaction's identity: the canonical ordering key.
    pub tx: TxHash,
    /// The transaction's declared effect set on this shard.
    pub declared: EffectSet,
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
    /// A fold failure while applying movements.
    #[error(transparent)]
    Mode(#[from] ModeError),
}

/// The executed batch: every receipt, canonically ordered, and the
/// committed store.
#[derive(Debug)]
pub struct BatchOutcome {
    /// Per-transaction receipts, in canonical order.
    pub receipts: BTreeMap<TxHash, Receipt>,
    /// Committed state after canonical-order application.
    pub store: MemoryStore,
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
    judged: &Arc<MemoryStore>,
    batch: &[&BatchTx],
    group: &[usize],
    runner: &R,
    env: EnvInputs,
    hash_fn: fn(&[u8]) -> [u8; 32],
) -> Result<Vec<(TxHash, Receipt)>, BatchError> {
    let mut receipts = Vec::with_capacity(group.len());
    let mut store = OverlayStore::new(Arc::clone(judged));
    for &index in group {
        let entry = batch[index];
        let before = store.clone();
        let session =
            match KernelSession::materialize(store, &entry.declared, entry.tx, env, hash_fn) {
                Ok(session) => {
                    // The rollback clone must drop here: it keeps the threaded
                    // layer's Arc unshared, so finish merges it in place.
                    drop(before);
                    session
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
                let (receipt, threaded) = result
                    .session
                    .finish(result.outcome, result.fuel)
                    .map_err(|source| BatchError::Finish {
                        tx: entry.tx,
                        source,
                    })?;
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
    committed: MemoryStore,
    batch: &[BatchTx],
    runner: &R,
    env: EnvInputs,
    hash_fn: fn(&[u8]) -> [u8; 32],
    mode: ExecutionMode,
) -> Result<BatchOutcome, BatchError> {
    let mut seen = std::collections::BTreeSet::new();
    for entry in batch {
        if !seen.insert(entry.tx) {
            return Err(BatchError::DuplicateTx(entry.tx));
        }
    }
    let mut ordered: Vec<&BatchTx> = batch.iter().collect();
    ordered.sort_by_key(|entry| entry.tx);
    let mut receipts: BTreeMap<TxHash, Receipt> = BTreeMap::new();

    // Judge every declared reservation in canonical order; hold the
    // feasible, abort the infeasible.
    let mut judged = committed;
    judged.clear_log();
    let mut requests = Vec::new();
    for entry in &ordered {
        for (key, amount) in declared_reservations(&entry.declared) {
            requests.push((entry.tx, key, amount));
        }
    }
    let verdicts = judged.judge_and_hold(&requests)?;
    let mut runnable: Vec<&BatchTx> = Vec::with_capacity(batch.len());
    for entry in ordered {
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

    // Group and execute; every group's overlay shares the judged store as
    // its immutable base.
    let judged = Arc::new(judged);
    let groups = conflict_groups(&runnable);
    let executed: Vec<Result<Vec<(TxHash, Receipt)>, BatchError>> = match mode {
        ExecutionMode::Serial => groups
            .iter()
            .map(|group| run_group(&judged, &runnable, group, runner, env, hash_fn))
            .collect(),
        ExecutionMode::Parallel => thread::scope(|scope| {
            #[allow(clippy::needless_collect)] // spawn every worker before joining any
            let handles: Vec<_> = groups
                .iter()
                .map(|group| {
                    let judged = &judged;
                    let runnable = &runnable;
                    scope.spawn(move || run_group(judged, runnable, group, runner, env, hash_fn))
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
    apply_receipts(&mut store, batch, &receipts)?;

    Ok(BatchOutcome { receipts, store })
}

/// Canonical-order application: absolute writes and entry changes, then
/// movement folds, settles for the completed, releases for the rest.
fn apply_receipts(
    store: &mut MemoryStore,
    batch: &[BatchTx],
    receipts: &BTreeMap<TxHash, Receipt>,
) -> Result<(), BatchError> {
    let mut deltas: Vec<(SubstateKey, DeltaOp)> = Vec::new();
    for (tx, receipt) in receipts {
        if matches!(receipt.outcome, Outcome::Completed { .. }) {
            for (key, change) in &receipt.delta.cells {
                match change {
                    Some(value) => store.write(*key, value.clone())?,
                    None => {
                        store.remove(*key)?;
                    }
                }
            }
            for ((owner, collection, order), change) in &receipt.delta.entries {
                match change {
                    Some(value) => store.entry_write(*owner, *collection, *order, value.clone())?,
                    None => {
                        store.entry_remove(*owner, *collection, *order)?;
                    }
                }
            }
            for (key, movement) in &receipt.delta.movements {
                deltas.push((*key, DeltaOp::Add(movement.credit)));
                deltas.push((*key, DeltaOp::Sub(movement.debit)));
            }
            for key in receipt.delta.settles.keys() {
                store.settle(*key, *tx)?;
            }
        } else {
            // Release whatever the judge held for an aborted transaction.
            for entry in batch.iter().filter(|entry| entry.tx == *tx) {
                for (key, _) in declared_reservations(&entry.declared) {
                    if store.held_reservation(key, *tx).is_some() {
                        store.release(key, *tx)?;
                    }
                }
            }
        }
    }
    for (key, op) in deltas {
        store.queue_delta(key, op)?;
    }
    store.commit_deltas()?;
    store.clear_log();
    Ok(())
}
