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
//!
//! Grouping is a pure function of the batch, so the outcome is
//! deterministic — but it is a function of the *grouping*, not of
//! canonical order alone. A transaction's debit is judged against its own
//! group's store, so it can flip to infeasible there even though a
//! canonically earlier transaction in a different group credited the same
//! cell; that credit becomes visible only at apply, where the converse
//! flip is handled. Every replica agrees, because every replica groups
//! identically — but a change to how batches are composed can change
//! which transaction loses a contested cell, and that is a property of
//! batch composition rather than of the executor.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Mode, ModeKind, RoleId, SubstateKey, compatible,
};

use crate::conflict::targets_overlap;
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

fn root(component: &mut [usize], mut index: usize) -> usize {
    while component[index] != index {
        component[index] = component[component[index]];
        index = component[index];
    }
    index
}

fn merge(component: &mut [usize], left: usize, right: usize) {
    let (a, b) = (root(component, left), root(component, right));
    component[a.max(b)] = a.min(b);
}

/// One collection's declarations: who declared it, over what interval, in
/// what mode.
type CollectionClaims = Vec<(usize, EffectTarget, ModeKind)>;

/// The transactions touching one point key, split by what the mode lattice
/// does with them.
///
/// Snapshots conflict with nothing. Reads are compatible with each other
/// and with snapshots; the commutative modes likewise. A write conflicts
/// with everything but a snapshot, itself included.
#[derive(Default)]
struct PointClasses {
    reads: Vec<usize>,
    commutative: Vec<usize>,
    writes: Vec<usize>,
}

impl PointClasses {
    fn push(&mut self, index: usize, kind: ModeKind) {
        match kind {
            ModeKind::Read => self.reads.push(index),
            ModeKind::Delta | ModeKind::Reserve => self.commutative.push(index),
            ModeKind::Write => self.writes.push(index),
            ModeKind::Snapshot => {}
        }
    }

    /// Connect this key's component in one pass rather than by pairwise
    /// comparison.
    ///
    /// A write conflicts with every other declaration here, so one write
    /// makes the whole key a single component. With no write, reads and
    /// the commutative modes are each internally compatible and conflict
    /// only across the divide — so they form one component when both are
    /// present and none when either is absent. Either way an anchor plus
    /// a linear walk reaches the same components the pairwise relation
    /// would.
    fn merge_into(&self, component: &mut [usize]) {
        let anchor = self.writes.first().or_else(|| {
            if self.reads.is_empty() || self.commutative.is_empty() {
                None
            } else {
                self.reads.first()
            }
        });
        let Some(&anchor) = anchor else {
            return;
        };
        for &index in self
            .reads
            .iter()
            .chain(&self.commutative)
            .chain(&self.writes)
        {
            merge(component, anchor, index);
        }
    }
}

/// Conflict groups over the batch: connected components of the conflict
/// relation, each sorted canonically.
///
/// Effects bucket by the key space they can alias — point keys by the key
/// itself, collection targets by `(owner, collection)` — so transactions
/// that could not possibly conflict are never compared. Point buckets then
/// resolve in one pass over the mode lattice. Interval targets stay
/// pairwise inside their own collection, where overlap is arithmetic and
/// the population is whoever declared that collection.
fn conflict_groups(batch: &[&BatchTx]) -> Vec<Vec<usize>> {
    let mut component: Vec<usize> = (0..batch.len()).collect();
    let mut points: BTreeMap<SubstateKey, PointClasses> = BTreeMap::new();
    let mut collections: BTreeMap<(Address, RoleId), CollectionClaims> = BTreeMap::new();

    for (index, entry) in batch.iter().enumerate() {
        for effect in entry.declared.iter() {
            let kind = effect.mode.kind();
            match effect.target {
                EffectTarget::Point(key) => points.entry(key).or_default().push(index, kind),
                EffectTarget::Entry {
                    owner, collection, ..
                }
                | EffectTarget::Range {
                    owner, collection, ..
                } => collections.entry((owner, collection)).or_default().push((
                    index,
                    effect.target,
                    kind,
                )),
            }
        }
    }

    for classes in points.values() {
        classes.merge_into(&mut component);
    }
    for touching in collections.values() {
        for (position, (left, left_target, left_kind)) in touching.iter().enumerate() {
            for (right, right_target, right_kind) in &touching[position + 1..] {
                if left != right
                    && !compatible(*left_kind, *right_kind)
                    && targets_overlap(left_target, right_target)
                {
                    merge(&mut component, *left, *right);
                }
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

/// How a materialization failure ends its transaction.
///
/// A declaration the world cannot honor is the sender's: they asked for a
/// mode on a target that cannot carry it. A held reservation that does not
/// match, or a store refusal, is the crate's own bookkeeping by its own
/// taxonomy — charging the sender for it would price our defect to them.
fn materialize_abort(defect: &MaterializeError) -> Outcome {
    match defect {
        MaterializeError::HeldMismatch(_) | MaterializeError::Store(_) => Outcome::ProtocolError {
            reason: defect.to_string(),
        },
        _ => Outcome::UserError {
            reason: defect.to_string(),
        },
    }
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
                    receipts.push((entry.tx, abort_receipt(materialize_abort(&defect), 0)));
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
/// # Declaration well-formedness
///
/// The executor judges exactly two things about the declarations it is
/// given, and both are batch-level facts nothing else can see: that no
/// transaction hash repeats, and that every nullifier a transaction
/// commits is declared as an exclusive write. Both fail the batch, because
/// neither transaction alone could have been judged on it.
///
/// Everything else about a declared set belongs to whoever built it —
/// that its modes compose, that its targets can carry them, that it is
/// what routing derived from the signed transaction — and is reported per
/// transaction: a set that cannot materialize aborts its own transaction
/// as a user error and the batch carries on without it. A batch-level
/// refusal discards other senders' work, so it stays reserved for what a
/// single transaction is not enough to decide.
///
/// # Errors
///
/// Any [`BatchError`] — all are kernel-level defects; per-transaction
/// failures land in receipts, never here.
///
/// # Panics
///
/// Only if a runner panics — the panic propagates from its worker — on the
/// kernel defect of a group overlay outliving its group, or if judging
/// wrote a cell and unpinned the batch's snapshots.
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
    // its immutable base. Snapshots resolve against that base, so judging
    // must not have written a cell — see `has_layered_cells`.
    assert!(
        !judged.has_layered_cells(),
        "judging wrote a cell, so every group's snapshots would pin to post-judge state"
    );
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
                .map(|handle| match handle.join() {
                    Ok(result) => result,
                    // Carry the worker's own panic rather than replacing
                    // it: the payload is the diagnostic.
                    Err(payload) => std::panic::resume_unwind(payload),
                })
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

/// Canonical-order application, one transaction at a time: each completed
/// transaction applies into the active layer, which merges when it lands
/// whole and is discarded when it does not — the same rollback the session
/// gives a transaction that loses its floor mid-flight. A completed
/// transaction whose local debit the floor no longer covers — earlier
/// transactions drained the cell — flips to an infeasible receipt here, its
/// fuel kept, its state never applied.
fn apply_receipts(
    store: &mut OverlayStore,
    batch: &[BatchTx],
    receipts: &mut BTreeMap<TxHash, Receipt>,
    locality: &Locality,
) -> Result<(), BatchError> {
    let entries: BTreeMap<TxHash, &BatchTx> = batch.iter().map(|entry| (entry.tx, entry)).collect();
    let order: Vec<TxHash> = receipts.keys().copied().collect();
    for tx in order {
        let receipt = receipts.get(&tx).expect("walked from keys");
        let completed = matches!(receipt.outcome, Outcome::Completed { .. });
        let fuel = receipt.fuel;
        let refusal = if completed {
            apply_completed(store, receipt, tx, locality)?
        } else {
            None
        };
        if let Some((key, amount)) = refusal {
            store.discard_active();
            receipts.insert(tx, abort_receipt(Outcome::Infeasible { key, amount }, fuel));
        }
        // A completed transaction settled its local holds and releases its
        // remote ones, where the settlement happened at the owning shard;
        // anything else releases every hold it still stands on.
        let settled_locally = completed && refusal.is_none();
        if let Some(entry) = entries.get(&tx) {
            for (key, _) in declared_reservations(&entry.declared) {
                if (!settled_locally || !locality.is_local(key.owner))
                    && store.held_reservation(key, tx).is_some()
                {
                    store.release(key, tx)?;
                }
            }
        }
        store.merge_active();
    }
    store.clear_log();
    Ok(())
}

/// One completed transaction's canonical application, on locally owned keys
/// only — remote operations stay in the receipt as the outbound effect
/// record. Absolute writes and entry changes, then movements under the
/// reservation floor, then settles.
///
/// Returns the key and amount of a deterministic refusal for the caller to
/// roll back; an error is a kernel defect. The two refusals are the ones
/// the session judges by the same taxonomy: a debit past the floor, and a
/// cell an exclusive write left below the reservations still standing on
/// it. Replay reaches the same verdicts the group overlay did — the same
/// canonical order over the same base, and the floor is invariant under
/// settle/movement ordering — so a refusal here is a defense against that
/// reasoning going stale, not a second judgement.
fn apply_completed(
    store: &mut OverlayStore,
    receipt: &Receipt,
    tx: TxHash,
    locality: &Locality,
) -> Result<Option<(SubstateKey, u128)>, BatchError> {
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
        match store.apply_movement(*key, movement.credit, movement.debit) {
            Ok(_) => {}
            Err(
                StoreError::Mode(ModeError::CellUnderflow | ModeError::CellOverflow)
                | StoreError::HeldExceedsCommitted(_),
            ) => return Ok(Some((*key, movement.debit))),
            Err(defect) => return Err(defect.into()),
        }
    }
    for key in receipt.delta.settles.keys() {
        if !locality.is_local(key.owner) {
            continue;
        }
        match store.settle(*key, tx) {
            Ok(_) => {}
            // The refusal left the hold standing, so the amount the
            // transaction lost is still readable.
            Err(StoreError::HeldExceedsCommitted(_)) => {
                let amount = store.held_reservation(*key, tx).unwrap_or_default();
                return Ok(Some((*key, amount)));
            }
            Err(defect) => return Err(defect.into()),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_vm_effects::{
        Address, Effect, EffectSet, EffectTarget, Hash32, Mode, RoleId, TestHasher, Window,
        child_key,
    };
    use proptest::collection::vec as prop_vec;
    use proptest::prelude::{Strategy, prop_oneof, proptest};

    use super::{BatchTx, Outcome, conflict_groups, materialize_abort, merge, root};
    use crate::conflict::conflicts;
    use crate::modes::{ModeError, TxHash};
    use crate::session::MaterializeError;
    use crate::store::StoreError;

    const BOOK: Address = Address([0x77; 16]);
    const ASKS: RoleId = RoleId(4);

    const fn nth_mode(index: u8) -> Mode {
        match index {
            0 => Mode::Read,
            1 => Mode::Snapshot {
                window: Window::Bounded(4),
            },
            2 => Mode::Delta,
            3 => Mode::Reserve { amount: 1 },
            _ => Mode::Write,
        }
    }

    /// One generated declaration, over a key space small enough that
    /// transactions actually collide.
    fn arb_effect() -> impl Strategy<Value = Effect> {
        prop_oneof![
            (0u8..4, 0u8..5).prop_map(|(key, mode)| Effect {
                target: EffectTarget::Point(child_key(
                    &TestHasher,
                    Address([0xC0 + key; 16]),
                    RoleId(1),
                    &[],
                )),
                mode: nth_mode(mode),
            }),
            (0u128..6, 0u8..2).prop_map(|(order, write)| Effect {
                target: EffectTarget::Entry {
                    owner: BOOK,
                    collection: ASKS,
                    order,
                },
                mode: if write == 0 { Mode::Read } else { Mode::Write },
            }),
            (0u128..6, 0u128..6, 0u8..2).prop_map(|(a, b, write)| Effect {
                target: EffectTarget::Range {
                    owner: BOOK,
                    collection: ASKS,
                    lo: a.min(b),
                    hi: a.max(b),
                    cap: 4,
                },
                mode: if write == 0 { Mode::Read } else { Mode::Write },
            }),
        ]
    }

    /// The conflict relation's components, computed the slow way: every
    /// pair of transactions, every pair of their effects.
    fn pairwise_groups(batch: &[&BatchTx]) -> Vec<Vec<usize>> {
        let mut component: Vec<usize> = (0..batch.len()).collect();
        for (left, first) in batch.iter().enumerate() {
            for (right, second) in batch.iter().enumerate().skip(left + 1) {
                let clashes = first
                    .declared
                    .iter()
                    .any(|a| second.declared.iter().any(|b| conflicts(&a, &b)));
                if clashes {
                    merge(&mut component, left, right);
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

    proptest! {
        /// The bucketed grouping is an optimisation of the conflict
        /// relation, and its correctness rests on three facts about the
        /// mode lattice: reads are internally compatible, the commutative
        /// modes are, and a write conflicts with everything but a snapshot.
        /// Those facts live in the lattice, where the optimisation cannot
        /// see them — so rather than argue the two agree, they are run
        /// against each other.
        #[test]
        fn bucketed_grouping_agrees_with_the_pairwise_relation(
            declarations in prop_vec(prop_vec(arb_effect(), 0..4), 1..6),
        ) {
            let batch: Vec<BatchTx> = declarations
                .iter()
                .enumerate()
                .map(|(index, effects)| {
                    let mut declared = EffectSet::new();
                    for effect in effects {
                        declared.insert(*effect).expect("unit reserve amounts");
                    }
                    BatchTx::new(
                        TxHash(Hash32([u8::try_from(index).expect("small batch"); 32])),
                        declared,
                        0,
                        [0; 32],
                    )
                })
                .collect();
            let entries: Vec<&BatchTx> = batch.iter().collect();
            assert_eq!(conflict_groups(&entries), pairwise_groups(&entries));
        }
    }

    /// Materialization failures split by whose fault they are.
    ///
    /// Neither kernel-defect arm is reachable through `execute_batch` —
    /// the batch judge overwrites a stale hold before materialization can
    /// see it, and the reserve pre-screen catches unusable targets — so
    /// the classification is asserted here rather than through a batch
    /// that cannot produce one.
    #[test]
    fn only_the_senders_own_defects_are_priced_to_them() {
        let key = child_key(&TestHasher, Address([1; 16]), RoleId(1), &[]);

        for sender_fault in [
            MaterializeError::LockedTarget(key),
            MaterializeError::SelfConflicting(key),
            MaterializeError::Unsupported(Effect {
                target: EffectTarget::Point(key),
                mode: Mode::Read,
            }),
        ] {
            assert!(
                matches!(materialize_abort(&sender_fault), Outcome::UserError { .. }),
                "{sender_fault:?} is the sender's declaration defect"
            );
        }

        for kernel_defect in [
            MaterializeError::HeldMismatch(key),
            MaterializeError::Store(StoreError::HeldExceedsCommitted(key)),
            MaterializeError::Store(StoreError::Mode(ModeError::BadAmountCell(3))),
        ] {
            assert!(
                matches!(
                    materialize_abort(&kernel_defect),
                    Outcome::ProtocolError { .. }
                ),
                "{kernel_defect:?} is our own bookkeeping"
            );
        }
    }
}
