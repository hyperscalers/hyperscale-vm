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
//! commutative by construction and locked reads cannot change);
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
    AbortReason, Address, CollectionId, Declaration, Effect, EffectSet, EffectTarget, Mode,
    ModeKind, NodeCall, SubstateKey, compatible,
};

use crate::locality::Locality;
use crate::modes::{ModeError, TxHash};
use crate::overlay::OverlayStore;
use crate::session::{
    EnvInputs, FinishError, KernelSession, MaterializeError, Outcome, Receipt, StateDelta,
};
use crate::store::{Baseline, StoreError, Substates, WorkingStore};
use crate::work::Work;

/// One transaction of a batch: its identity and its routed effect set.
#[derive(Clone, Debug)]
pub struct BatchTx {
    /// The transaction's identity: the canonical ordering key.
    pub tx: TxHash,
    /// The transaction's declared effect set on this shard: folded,
    /// canonically ordered, reserve amounts on one target summed.
    ///
    /// What scheduling reads. [`conflict_groups`] groups on it,
    /// reservation judging judges against it, and the folding is
    /// load-bearing for both.
    pub declared: EffectSet,
    /// The same declaration in clause-evaluation order, one entry per
    /// clause the signature reached.
    ///
    /// What capability materialization reads, because a handle's rep is
    /// its index into the materialized table and a guest's parameters are
    /// positional. [`BatchTx::declared`] cannot serve: its order is a
    /// comparison over hash-derived keys, and its *length* shrinks
    /// whenever two clauses evaluate to one target — which would make a
    /// guest's parameter list depend on instance configuration rather
    /// than on its own signature.
    ///
    /// Must fold to [`BatchTx::declared`]; [`execute_batch`] checks it.
    pub ordered: Vec<Effect>,
    /// The transaction's lowered invocations, in manifest node order:
    /// what [`crate::walk::ManifestWalk`] performs.
    ///
    /// Shard-invariant, exactly like [`BatchTx::ordered`] and for the
    /// same reason — every participant of a cross-shard transaction runs
    /// the identical calls against the identical table, and locality
    /// scopes what is applied rather than what is invoked.
    pub calls: Vec<NodeCall>,
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
    /// The signed execution ceiling, in fuel.
    ///
    /// Per transaction, not per invocation: a manifest's nodes draw from
    /// one budget, so what the sender declared bounds what the whole
    /// transaction can consume rather than what each of its calls can.
    /// Exhaustion is the sender's own defect and prices as one.
    pub gas_limit: u64,
}

impl BatchTx {
    /// A transaction with no bound subintents.
    ///
    /// Takes the whole [`Declaration`] rather than either view, so the two
    /// cannot be paired wrongly on this path. The environment inputs are
    /// arguments rather than defaults: a silently zeroed clock or draw is
    /// a wrong consensus input that nothing would catch.
    #[must_use]
    pub fn new(
        tx: TxHash,
        declaration: impl Into<Declaration>,
        clock_ms: u64,
        randomness: [u8; 32],
    ) -> Self {
        let declaration = declaration.into();
        Self {
            tx,
            declared: declaration.set,
            ordered: declaration.ordered,
            calls: Vec::new(),
            nullifiers: Vec::new(),
            clock_ms,
            randomness,
            gas_limit: u64::MAX,
        }
    }

    /// Bind the signed execution ceiling. Unset means unbounded, which is
    /// what an in-crate fixture wants and what no embedder should leave
    /// it at: the envelope always carries one.
    #[must_use]
    pub const fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Bind the invocations the manifest walk performs.
    #[must_use]
    pub fn with_calls(mut self, calls: Vec<NodeCall>) -> Self {
        self.calls = calls;
        self
    }

    /// Bind the subintents this transaction commits. Each key must also be
    /// declared as an exclusive write.
    #[must_use]
    pub fn with_nullifiers(mut self, nullifiers: Vec<SubstateKey>) -> Self {
        self.nullifiers = nullifiers;
        self
    }
}

/// The seam between the executor's per-transaction bookkeeping and the
/// guest work a transaction performs.
///
/// The implementation every embedder wants is [`crate::walk::ManifestWalk`],
/// which walks the transaction's own lowered invocations over a
/// [`crate::walk::GuestBackend`]. The trait stays open because the
/// executor's own mechanics — reservation adoption, group threading,
/// rollback, the apply-time floor — are properties of the session and not
/// of any manifest, and scripting a session directly is how they are
/// tested.
pub trait GuestRunner: Sync {
    /// Execute the transaction, returning the session, how it ended, and
    /// the fuel consumed.
    fn run(&self, entry: &BatchTx, session: KernelSession) -> RunResult;
}

impl<F> GuestRunner for F
where
    F: Fn(&BatchTx, KernelSession) -> RunResult + Sync,
{
    fn run(&self, entry: &BatchTx, session: KernelSession) -> RunResult {
        self(entry, session)
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
    /// A transaction's two declaration views disagree: folding
    /// [`BatchTx::ordered`] does not reproduce [`BatchTx::declared`].
    ///
    /// The pair is one declaration seen two ways, and every consumer picks
    /// the view its job needs — scheduling and judging read the set,
    /// capability materialization reads the clause list. Letting them
    /// diverge would let a transaction be routed against one declaration
    /// and handed capabilities for another.
    #[error("transaction {tx:?} has inconsistent declaration views")]
    InconsistentDeclaration {
        /// The offending transaction.
        tx: TxHash,
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

/// The executed batch: every receipt, canonically ordered, the work this
/// shard attests for each, and the end state.
#[derive(Debug)]
pub struct BatchOutcome {
    /// Per-transaction receipts, in canonical order.
    ///
    /// Identical at every participant of a cross-shard transaction: the
    /// receipt is the outbound effect record, filtered at apply rather
    /// than at derivation.
    pub receipts: BTreeMap<TxHash, Receipt>,
    /// Per-transaction attested work, keyed alongside the receipts and
    /// covering every one of them, whatever the verdict.
    ///
    /// This shard's share, so unlike a receipt it is *expected* to differ
    /// between the participants of one transaction — see [`Work`].
    pub work: BTreeMap<TxHash, Work>,
    /// The end state: the given base untouched, with the batch's full
    /// delta in the overlay's committed layer.
    pub store: OverlayStore,
}

/// Price every receipt the batch produced, in one pass over the finished
/// map.
///
/// Deliberately not threaded through the construction sites. A receipt
/// leaves this executor by a lot of routes — two refusals before any group
/// runs, four abort exits inside one, the session's own refusals in
/// `finish`, the completed path, and the apply-time flip from completed to
/// infeasible — and a work term missing at any of them would not fail, it
/// would under-report. Derived once, at the end, from the finished verdict
/// and the declaration behind it, there is no site left to forget.
///
/// Running after `apply_receipts` is what makes the flip free: a completed
/// transaction that lost its floor is already infeasible here, so it drops
/// its fuel term without anything having to notice that it changed.
fn attest_work(
    batch: &[BatchTx],
    receipts: &BTreeMap<TxHash, Receipt>,
    locality: &Locality,
) -> BTreeMap<TxHash, Work> {
    let declared: BTreeMap<TxHash, &EffectSet> = batch
        .iter()
        .map(|entry| (entry.tx, &entry.declared))
        .collect();
    receipts
        .iter()
        .map(|(tx, receipt)| {
            // Every receipt came from a batch entry, so the lookup holds;
            // a declaration that vanished would be a kernel defect, and
            // pricing it at zero states that rather than guessing.
            let footprint = declared.get(tx).map_or(0, |set| locality.footprint(set));
            (
                *tx,
                Work::attest(
                    matches!(receipt.outcome, Outcome::Completed { .. }),
                    receipt.fuel,
                    footprint,
                ),
            )
        })
        .collect()
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

const fn root(component: &mut [usize], mut index: usize) -> usize {
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

/// Which side of the mode lattice a collection claim sits on.
///
/// The three classes the sweep distinguishes: a locked claim conflicts
/// with nothing and never becomes one. Reads are compatible with reads and
/// the commutative modes with each other; every other pairing conflicts —
/// which is what lets the sweep decide conflict from the classes alone.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimClass {
    Read,
    Commutative,
    Write,
}

impl ClaimClass {
    /// Every class, in the order the sweep's active lists are indexed.
    const ALL: [Self; 3] = [Self::Read, Self::Commutative, Self::Write];

    /// The class of a mode kind, or `None` for one that conflicts with
    /// nothing and so cannot join a group.
    const fn of(kind: ModeKind) -> Option<Self> {
        match kind {
            ModeKind::Locked => None,
            ModeKind::Read => Some(Self::Read),
            ModeKind::Delta | ModeKind::Reserve => Some(Self::Commutative),
            ModeKind::Write => Some(Self::Write),
        }
    }

    /// A mode kind standing for this class.
    ///
    /// The commutative modes are interchangeable under [`compatible`], so
    /// one of them speaks for both and conflict stays read off the lattice
    /// rather than tabulated again beside it.
    const fn kind(self) -> ModeKind {
        match self {
            Self::Read => ModeKind::Read,
            Self::Commutative => ModeKind::Delta,
            Self::Write => ModeKind::Write,
        }
    }

    /// Which active list this class occupies.
    const fn slot(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Commutative => 1,
            Self::Write => 2,
        }
    }

    const fn conflicts_with(self, other: Self) -> bool {
        !compatible(self.kind(), other.kind())
    }
}

/// One claim on a collection: who declared it, the interval it names, and
/// its side of the lattice.
struct CollectionClaim {
    tx: usize,
    lo: u128,
    hi: u128,
    class: ClaimClass,
}

/// One collection's claims, in declaration order until the sweep sorts
/// them.
type CollectionClaims = Vec<CollectionClaim>;

/// The interval a collection target names, or `None` where it names
/// nothing an overlap could land in.
///
/// An inverted range is empty — the store reads it as empty and the
/// pairwise relation finds it overlapping nothing, itself included — so it
/// joins no group and the sweep never sees it. That matters beyond
/// tidiness: the sweep's invariant is that an active claim contains the
/// sweep point, and an empty interval contains nothing.
const fn claim_interval(target: &EffectTarget) -> Option<(u128, u128)> {
    match target {
        EffectTarget::Entry { order, .. } => Some((*order, *order)),
        EffectTarget::Range { lo, hi, .. } if *lo <= *hi => Some((*lo, *hi)),
        EffectTarget::Range { .. } | EffectTarget::Point(_) => None,
    }
}

/// The claims of one class the sweep is still inside: how far each reaches,
/// and a transaction standing for the component it belongs to.
///
/// Every entry contains the sweep point, so any two of them overlap and so
/// does anything arriving next — which is why the sweep tests no intervals
/// at all once the claims are ordered.
type Active = Vec<(u128, usize)>;

/// Merge `claim` with every unexpired entry of a conflicting class and
/// collapse that class to the one component they now share, returning how
/// far it reaches.
///
/// Collapsing is what keeps the sweep linear. Reads do not conflict with
/// reads, so they pile up unmerged; the first commutative or exclusive
/// claim to arrive conflicts with all of them at once, and afterwards they
/// are one component that a single entry can speak for. Every entry is
/// therefore drained at most once, and each drain leaves one behind.
fn absorb(active: &mut Active, component: &mut [usize], claim: usize, lo: u128) -> Option<u128> {
    let mut reach: Option<u128> = None;
    for (hi, representative) in std::mem::take(active) {
        // A claim the sweep has passed cannot overlap what comes next, and
        // merging it here would group transactions that never met.
        if hi < lo {
            continue;
        }
        merge(component, claim, representative);
        reach = Some(reach.map_or(hi, |far: u128| far.max(hi)));
    }
    reach
}

/// Group one collection's claims by interval overlap in a single ordered
/// pass.
///
/// Sorting by interval start is what turns overlap into a question about
/// the sweep point rather than about pairs: everything still active begins
/// at or before the arriving claim and has not yet ended, so it overlaps.
/// What remains is the lattice, which the classes answer.
fn sweep_collection(claims: &mut CollectionClaims, component: &mut [usize]) {
    // A total order over signed content, so every replica sweeps the same
    // sequence and derives the same groups.
    claims.sort_unstable_by_key(|claim| (claim.lo, claim.hi, claim.tx));
    let mut active: [Active; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for claim in claims.iter() {
        let mut reach = claim.hi;
        for class in ClaimClass::ALL {
            if !claim.class.conflicts_with(class) {
                continue;
            }
            let Some(far) = absorb(&mut active[class.slot()], component, claim.tx, claim.lo) else {
                continue;
            };
            if class == claim.class {
                // Its own class, so the component just collapsed is the one
                // this claim leaves behind: its reach folds into the entry.
                reach = reach.max(far);
            } else {
                active[class.slot()].push((far, claim.tx));
            }
        }
        active[claim.class.slot()].push((reach, claim.tx));
    }
}

/// The transactions touching one point key, split by what the mode lattice
/// does with them.
///
/// Locked reads conflict with nothing. Reads are compatible with each
/// other and with locked reads; the commutative modes likewise. A write
/// conflicts with everything but a locked read, itself included.
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
            ModeKind::Locked => {}
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
/// that could not possibly conflict are never compared. A point bucket
/// resolves in one pass over the mode lattice, every claim in it naming the
/// same key. A collection bucket resolves in one ordered sweep, where
/// sorting by interval start makes overlap a property of the sweep point
/// and leaves only the lattice to decide.
fn conflict_groups(batch: &[&BatchTx]) -> Vec<Vec<usize>> {
    let mut component: Vec<usize> = (0..batch.len()).collect();
    let mut points: BTreeMap<SubstateKey, PointClasses> = BTreeMap::new();
    let mut collections: BTreeMap<(Address, CollectionId), CollectionClaims> = BTreeMap::new();

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
                } => {
                    // A claim conflicting with nothing, or naming an empty
                    // interval, joins no group and never enters the sweep.
                    let (Some(class), Some((lo, hi))) =
                        (ClaimClass::of(kind), claim_interval(&effect.target))
                    else {
                        continue;
                    };
                    collections
                        .entry((owner, collection))
                        .or_default()
                        .push(CollectionClaim {
                            tx: index,
                            lo,
                            hi,
                            class,
                        });
                }
            }
        }
    }

    for classes in points.values() {
        classes.merge_into(&mut component);
    }
    for claims in collections.values_mut() {
        sweep_collection(claims, &mut component);
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
/// A reservation the committed balance cannot cover is neither: it is the
/// lost race the taxonomy names, and it carries the cell and the amount
/// rather than a class.
fn materialize_abort(defect: MaterializeError) -> Outcome {
    match defect {
        MaterializeError::Infeasible { key, amount } => Outcome::Infeasible { key, amount },
        MaterializeError::HeldMismatch(_) => Outcome::ProtocolError {
            reason: AbortReason::ReservationMismatch,
        },
        MaterializeError::Store(store) => Outcome::ProtocolError {
            reason: store.into(),
        },
        MaterializeError::Unsupported(_) => Outcome::UserError {
            reason: AbortReason::EffectUnsupported,
        },
        MaterializeError::MutationOfLocked(_) => Outcome::UserError {
            reason: AbortReason::MutationOfLocked,
        },
        MaterializeError::UnlockedTarget(_) => Outcome::UserError {
            reason: AbortReason::LockedReadOfUnlocked,
        },
        MaterializeError::SelfConflicting(_) => Outcome::UserError {
            reason: AbortReason::SelfConflictingModes,
        },
    }
}

fn abort_receipt(outcome: Outcome, fuel: u64) -> Receipt {
    Receipt {
        outcome,
        delta: StateDelta::default(),
        events: Vec::new(),
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
    let shared: Arc<dyn Baseline> = Arc::<OverlayStore>::clone(judged);
    let mut store = OverlayStore::new(shared);
    for &index in group {
        let entry = batch[index];
        // A spent nullifier aborts before execution: some earlier
        // transaction — this group, an earlier batch, or the signer's
        // own cancellation — already committed the subintent. Only the
        // signer's shard holds the cell; elsewhere the owning shard's
        // verdict arrives through the tick combine.
        let spent = entry
            .nullifiers
            .iter()
            .find(|key| locality.is_local(key.owner) && store.cell(**key).is_some());
        if let Some(key) = spent {
            receipts.push((
                entry.tx,
                abort_receipt(Outcome::NullifierSpent { key: *key }, 0),
            ));
            continue;
        }
        let before = store.clone();
        let env = EnvInputs {
            clock_ms: entry.clock_ms,
            randomness: entry.randomness,
        };
        let session = match KernelSession::materialize(
            store,
            &entry.declared,
            &entry.ordered,
            entry.tx,
            env,
            hash_fn,
        ) {
            Ok(session) => {
                // The rollback clone must drop here: it keeps the threaded
                // layer's Arc unshared, so finish merges it in place.
                drop(before);
                session.with_locality(locality.clone())
            }
            Err(defect) => {
                receipts.push((entry.tx, abort_receipt(materialize_abort(defect), 0)));
                store = before;
                continue;
            }
        };
        let result = runner.run(entry, session);
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
                        reason: error.into(),
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

/// Batch-level well-formedness, checked before anything is judged or run.
///
/// Every failure here is a defect in whoever composed the batch, not a
/// transaction-level abort — so the batch refuses rather than producing
/// receipts that would encode the defect.
fn screen_batch(batch: &[BatchTx]) -> Result<(), BatchError> {
    let mut seen = std::collections::BTreeSet::new();
    for entry in batch {
        if !seen.insert(entry.tx) {
            return Err(BatchError::DuplicateTx(entry.tx));
        }

        // The two declaration views are one declaration; a caller building
        // the struct literally could pair them wrongly, and the
        // consequence would be a transaction routed against one
        // declaration and handed capabilities for another.
        let mut folded = EffectSet::new();
        for effect in &entry.ordered {
            folded
                .insert(*effect)
                .map_err(|_| BatchError::InconsistentDeclaration { tx: entry.tx })?;
        }
        if folded != entry.declared {
            return Err(BatchError::InconsistentDeclaration { tx: entry.tx });
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
    Ok(())
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
/// wrote a cell and moved the batch's baseline.
pub fn execute_batch<R: GuestRunner>(
    base: Arc<dyn Baseline>,
    batch: &[BatchTx],
    runner: &R,
    hash_fn: fn(&[u8]) -> [u8; 32],
    mode: ExecutionMode,
    locality: &Locality,
) -> Result<BatchOutcome, BatchError> {
    screen_batch(batch)?;
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
    // its immutable base. Locked reads resolve against that base, so judging
    // must not have written a cell — see `has_layered_cells`.
    assert!(
        !judged.has_layered_cells(),
        "judging wrote a cell, so every group's locked reads would resolve against post-judge state"
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

    let work = attest_work(batch, &receipts, locality);
    Ok(BatchOutcome {
        receipts,
        work,
        store,
    })
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
    let owned = receipt.delta.owned(locality);
    for (key, change) in owned.cells() {
        match change {
            Some(value) => store.write(key, value.clone())?,
            None => {
                store.remove(key)?;
            }
        }
    }
    for (key, change) in owned.entries() {
        match change {
            Some(value) => {
                store.entry_write(key.owner, key.collection, key.order, value.clone())?;
            }
            None => {
                store.entry_remove(key.owner, key.collection, key.order)?;
            }
        }
    }
    for (key, movement) in owned.movements() {
        match store.apply_movement(key, movement.credit, movement.debit) {
            Ok(_) => {}
            Err(
                StoreError::Mode(ModeError::CellUnderflow | ModeError::CellOverflow)
                | StoreError::HeldExceedsCommitted(_),
            ) => return Ok(Some((key, movement.debit))),
            Err(defect) => return Err(defect.into()),
        }
    }
    for (key, _) in owned.settles() {
        match store.settle(key, tx) {
            Ok(_) => {}
            // The refusal left the hold standing, so the amount the
            // transaction lost is still readable.
            Err(StoreError::HeldExceedsCommitted(_)) => {
                let amount = store.held_reservation(key, tx).unwrap_or_default();
                return Ok(Some((key, amount)));
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
        Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, Hash32, Mode, RoleId,
        TestHasher, child_key,
    };
    use proptest::collection::vec as prop_vec;
    use proptest::prelude::{Strategy, prop_oneof, proptest};

    use super::{BatchTx, Outcome, conflict_groups, materialize_abort, merge, root};
    use crate::conflict::conflicts;
    use crate::modes::{ModeError, TxHash};
    use crate::session::MaterializeError;
    use crate::store::StoreError;

    const BOOK: Address = Address::new([0x77; 31], AddressClass::Component);
    const ASKS: CollectionId = CollectionId([4; 16]);

    const fn nth_mode(index: u8) -> Mode {
        match index {
            0 => Mode::Read,
            1 => Mode::Locked,
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
                    Address::new([0xC0 + key; 31], AddressClass::Component),
                    RoleId(1),
                    &[],
                )),
                mode: nth_mode(mode),
            }),
            // Every mode on a collection target, not just read and write:
            // the commutative modes are what make a read conflict with
            // something a read does not, and the sweep collapses reads
            // precisely when one arrives.
            (0u128..6, 0u8..5).prop_map(|(order, mode)| Effect {
                target: EffectTarget::Entry {
                    owner: BOOK,
                    collection: ASKS,
                    order,
                },
                mode: nth_mode(mode),
            }),
            (0u128..6, 0u128..6, 0u8..5).prop_map(|(a, b, mode)| Effect {
                target: EffectTarget::Range {
                    owner: BOOK,
                    collection: ASKS,
                    lo: a.min(b),
                    hi: a.max(b),
                    cap: 4,
                },
                mode: nth_mode(mode),
            }),
            // Inverted intervals name nothing and must group nothing.
            (0u128..6, 0u128..6, 0u8..5).prop_map(|(a, b, mode)| Effect {
                target: EffectTarget::Range {
                    owner: BOOK,
                    collection: ASKS,
                    lo: a.max(b).saturating_add(1),
                    hi: a.min(b),
                    cap: 4,
                },
                mode: nth_mode(mode),
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
        /// modes are, and a write conflicts with everything but a locked read.
        /// Those facts live in the lattice, where the optimisation cannot
        /// see them — so rather than argue the two agree, they are run
        /// against each other.
        ///
        /// The collection sweep rests on more than the lattice: that
        /// sorting by interval start makes every active claim overlap what
        /// arrives, and that collapsing a class after it is absorbed loses
        /// no edge. Neither is visible to the pairwise relation, which
        /// compares every pair and tests every interval, so it is the
        /// oracle for both.
        #[test]
        fn bucketed_grouping_agrees_with_the_pairwise_relation(
            declarations in prop_vec(prop_vec(arb_effect(), 0..7), 1..9),
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
        let key = child_key(
            &TestHasher,
            Address::new([1; 31], AddressClass::Component),
            RoleId(1),
            &[],
        );

        for sender_fault in [
            MaterializeError::MutationOfLocked(key),
            MaterializeError::SelfConflicting(key),
            MaterializeError::Unsupported(Box::new(Effect {
                target: EffectTarget::Point(key),
                mode: Mode::Read,
            })),
        ] {
            assert!(
                matches!(
                    materialize_abort(sender_fault.clone()),
                    Outcome::UserError { .. }
                ),
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
                    materialize_abort(kernel_defect.clone()),
                    Outcome::ProtocolError { .. }
                ),
                "{kernel_defect:?} is our own bookkeeping"
            );
        }
    }
}
