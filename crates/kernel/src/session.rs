//! The per-transaction kernel session: capability materialization, the
//! mode operations behind the world's handles, and the receipt.
//!
//! A session is built from a declared effect set. Materialization turns
//! each declared effect into one [`Capability`] — the table the runtimes'
//! handle reps index — judging and holding reservations as it goes, so an
//! infeasible reservation aborts before any guest runs. During execution
//! the engines' host adapters delegate every world operation here; each
//! refusal is a deterministic message, identical on every replica because
//! the session itself generates it on both runtimes.
//!
//! [`KernelSession::finish`] is where the trace-subset oracle stands
//! permanently: it folds queued deltas, settles this transaction's
//! reservations, verifies every recorded access against the declared set,
//! and only then produces the receipt — outcome, state delta, fuel.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::{
    AbortReason, Address, CollectionId, Effect, EffectSet, EffectTarget, EntryKey, Mode, ModeKind,
    SubstateKey,
};

use crate::locality::Locality;
use crate::modes::{DeltaOp, ModeError, TxHash, decode_amount, encode_amount};
use crate::oracle::undeclared_accesses;
use crate::overlay::OverlayStore;
use crate::store::{Access, StoreError, WorkingStore};

/// One materialized capability: what a handle rep grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// A fresh read of one cell.
    Read(SubstateKey),
    /// A pinned read of one cell.
    Locked(SubstateKey),
    /// An exclusive read-modify-write of one cell.
    Write(SubstateKey),
    /// Commutative movement on one amount cell.
    Delta(SubstateKey),
    /// A held reservation on one amount cell, at this clause's own
    /// declared amount. The store's hold is the per-transaction fold
    /// over every reservation on the cell, so the clause's share rides
    /// the capability — the one place it still exists after the fold.
    Reserve {
        /// The reserved cell.
        key: SubstateKey,
        /// What this clause declared, not the folded hold.
        amount: u128,
    },
    /// A read interval of an ordered collection.
    RangeRead {
        /// The collection's owner.
        owner: Address,
        /// The collection's identity under the owner.
        collection: CollectionId,
        /// Inclusive lower order-key bound.
        lo: u128,
        /// Inclusive upper order-key bound.
        hi: u128,
        /// The declared entry cap.
        cap: u32,
    },
    /// A read-modify-write interval of an ordered collection.
    RangeWrite {
        /// The collection's owner.
        owner: Address,
        /// The collection's identity under the owner.
        collection: CollectionId,
        /// Inclusive lower order-key bound.
        lo: u128,
        /// Inclusive upper order-key bound.
        hi: u128,
        /// The declared entry cap: a scan truncates at it, and it bounds
        /// the distinct entries this interval may change — separately,
        /// since a read-modify-write reaches its whole page and an insert
        /// adds entries no scan returned.
        cap: u32,
    },
}

/// The rep an issuance grant is handed out under.
///
/// An invocation is granted issuance or it is not, so there is one, and
/// the constant is what says the number carries no information.
pub const ISSUER_REP: u32 = 0;

/// Why materialization refused a declared effect set — each an abort
/// before any guest execution.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MaterializeError {
    /// A declared mode/target combination the world cannot yet hand out.
    #[error("no capability form for {0:?}")]
    Unsupported(Box<Effect>),
    /// A mutation declared on a permanently locked substate.
    #[error("declared mutation of locked substate {0:?}")]
    MutationOfLocked(SubstateKey),
    /// A locked read declared on a substate that is not locked. The mode
    /// reads without coherence and without making a participant, which is
    /// sound only where no version of the target differs.
    #[error("declared locked read of unlocked substate {0:?}")]
    UnlockedTarget(SubstateKey),
    /// A declared reservation the committed balance cannot cover.
    #[error("reservation of {amount} on {key:?} is infeasible")]
    Infeasible {
        /// The cell reserved against.
        key: SubstateKey,
        /// The declared amount.
        amount: u128,
    },
    /// One transaction declaring an exclusive and a commutative mode on
    /// the same cell — absolute and movement semantics cannot compose
    /// within one receipt.
    #[error("write and delta/reserve declared on the same cell {0:?}")]
    SelfConflicting(SubstateKey),
    /// An already-held reservation whose amount differs from the declared
    /// one — a batch bookkeeping defect, surfaced rather than adopted.
    #[error("held reservation on {0:?} does not match the declaration")]
    HeldMismatch(SubstateKey),
    /// A store failure while judging reservations.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A deterministic host refusal during execution: the same abort class on
/// every replica.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionTrap {
    /// A rep with no table entry — unreachable through either runtime's
    /// canonical ABI, kept as an honest error rather than a panic.
    #[error("unknown capability handle {0}")]
    UnknownHandle(u32),
    /// A rep whose capability does not grant the operation — unreachable
    /// through the typed world surface, kept as an honest error.
    #[error("handle {0} does not grant this operation")]
    WrongMode(u32),
    /// An entry index past the interval's current entries.
    #[error("entry index {index} out of bounds ({count} entries)")]
    IndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// Entries currently visible in the interval.
        count: usize,
    },
    /// An insert order outside the declared interval.
    #[error("order outside the declared interval")]
    OrderOutsideInterval,
    /// More distinct entries written through one interval than the cap it
    /// declared. A scan truncates at the cap; a write has no natural
    /// truncation, so passing it is a refusal rather than a silent
    /// over-run of what the declaration claimed.
    #[error("interval has written its declared cap of {cap} entries")]
    WriteCapExceeded {
        /// The interval's declared entry cap.
        cap: u32,
        /// The order the refused write would have added.
        order: u128,
    },
    /// A reservation the table promises but the store no longer holds —
    /// unreachable, kept honest.
    #[error("no reservation held")]
    ReservationMissing,
    /// A second take of one reservation. The grant is a quantity, and it
    /// leaves the kernel once.
    #[error("reservation already taken")]
    ReservationTaken,
    /// An issue by an invocation that was granted none — unreachable
    /// through a lowered handle, kept as an honest error.
    #[error("this invocation issues nothing")]
    IssuanceUngranted,
    /// A stored cell a movement reads as an amount and cannot: a defect
    /// in state rather than in the call that found it.
    #[error("substate {0:?} is not an amount cell")]
    BadAmountCell(SubstateKey),
    /// A debit past what an absolute cell holds, judged at the call
    /// because an absolute resolves there.
    #[error("debit exceeds the cell's balance")]
    CellUnderflow,
    /// A credit past the cell's own width, on the same terms.
    #[error("credit exceeds the cell's width")]
    CellOverflow,
    /// An emission outside any invocation, so the kernel has no address to
    /// stamp — unreachable through a runner that enters every node.
    #[error("emission outside an invocation")]
    NoInvocation,
    /// An event type past the per-package ceiling.
    #[error("event type {0} past the ceiling")]
    EventTypeOutOfRange(u32),
    /// More events than a transaction may emit.
    #[error("event count past the cap of {MAX_EVENTS_PER_TX}")]
    TooManyEvents,
    /// An event payload past the per-event byte cap.
    #[error("event payload of {0} bytes past the cap of {MAX_EVENT_PAYLOAD_BYTES}")]
    EventPayloadTooLarge(usize),
    /// A store refusal.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<SessionTrap> for AbortReason {
    fn from(trap: SessionTrap) -> Self {
        match trap {
            SessionTrap::UnknownHandle(_) => Self::HandleUnknown,
            SessionTrap::WrongMode(_) => Self::HandleWrongMode,
            SessionTrap::IndexOutOfBounds { .. } => Self::EntryIndexOutOfBounds,
            SessionTrap::OrderOutsideInterval => Self::OrderOutsideInterval,
            SessionTrap::WriteCapExceeded { .. } => Self::IntervalWriteCapExceeded,
            SessionTrap::ReservationMissing => Self::ReservationMissing,
            SessionTrap::ReservationTaken => Self::ReservationAlreadyTaken,
            SessionTrap::IssuanceUngranted => Self::IssuanceUngranted,
            SessionTrap::BadAmountCell(_) => Self::MalformedAmountCell,
            SessionTrap::CellUnderflow => Self::CellUnderflow,
            SessionTrap::CellOverflow => Self::CellOverflow,
            SessionTrap::NoInvocation => Self::EmissionOutsideInvocation,
            SessionTrap::EventTypeOutOfRange(_) => Self::EventTypeOutOfRange,
            SessionTrap::TooManyEvents => Self::EventCountExceeded,
            SessionTrap::EventPayloadTooLarge(_) => Self::EventPayloadTooLarge,
            SessionTrap::Store(store) => store.into(),
        }
    }
}

// The emission caps and the event record are the shared vocabulary: the
// same constants bound the kernel's emission here and the wire's decode in
// the consensus workspace, so the two cannot drift.
pub use hyperscale_vm_effects::{
    Event, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX,
};

/// The deterministic environment a transaction executes under.
#[derive(Clone, Copy, Debug)]
pub struct EnvInputs {
    /// The transaction clock in milliseconds.
    pub clock_ms: u64,
    /// The transaction's randomness draw.
    pub randomness: [u8; 32],
}

/// How execution ended — the shared abort taxonomy, whose docs live with
/// the type.
pub use hyperscale_vm_effects::Outcome;
pub use hyperscale_vm_types::Movement;

/// The committed state change, keyed canonically: `None` is a removal.
/// Exclusive accesses report absolute outcomes; commutative accesses
/// report movements.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateDelta {
    /// Cells changed under exclusive write capabilities.
    pub cells: DeltaMap<SubstateKey, Option<Vec<u8>>>,
    /// Changed ordered-collection entries.
    pub entries: DeltaMap<EntryKey, Option<Vec<u8>>>,
    /// Delta movements per amount cell.
    pub movements: DeltaMap<SubstateKey, Movement>,
    /// Settled reservation amounts per cell.
    pub settles: DeltaMap<SubstateKey, u128>,
}

/// One kind of change a receipt carries, keyed by what it changes.
///
/// Lookup is open: asking whether a receipt changed a named key is a
/// question about that key, and the answer does not depend on who is
/// asking. Walking is not open, because every walk of a receipt exists to
/// apply it somewhere, and the shard applying it owns only part of what the
/// receipt carries — the rest is the outbound record for the shard that
/// does. So iteration is reachable only through [`StateDelta::owned`], and
/// a walk that skips the locality check stops being a review question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaMap<K: Ord, V> {
    entries: BTreeMap<K, V>,
}

// Derived `Default` would demand it of the key and the value; an empty map
// needs neither.
impl<K: Ord, V> Default for DeltaMap<K, V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K: Ord, V> DeltaMap<K, V> {
    /// The change recorded at `key`, if any.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.get(key)
    }

    /// Whether a change is recorded at `key`.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.contains_key(key)
    }

    /// Whether nothing of this kind changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many keys changed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Record a change, replacing any at the same key.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.entries.insert(key, value)
    }

    /// Drop the changes `keep` refuses.
    pub fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool) {
        self.entries.retain(keep);
    }

    /// The whole map, for the crate that owns the locality rule. Consumers
    /// reach it through [`StateDelta::owned`].
    #[allow(clippy::iter_without_into_iter)] // an IntoIterator restores the unfiltered walk
    pub(crate) fn iter(&self) -> std::collections::btree_map::Iter<'_, K, V> {
        self.entries.iter()
    }
}

impl<K: Ord, V> From<BTreeMap<K, V>> for DeltaMap<K, V> {
    fn from(entries: BTreeMap<K, V>) -> Self {
        Self { entries }
    }
}

impl<K: Ord + std::borrow::Borrow<Q>, Q: Ord + ?Sized, V> std::ops::Index<&Q> for DeltaMap<K, V> {
    type Output = V;

    fn index(&self, key: &Q) -> &V {
        &self.entries[key]
    }
}

impl StateDelta {
    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
            && self.entries.is_empty()
            && self.movements.is_empty()
            && self.settles.is_empty()
    }
}

/// The transaction's receipt: a pure function of committed content and the
/// signed transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// How execution ended.
    pub outcome: Outcome,
    /// What committed.
    pub delta: StateDelta,
    /// What the transaction said happened, in emission order.
    ///
    /// Carried on every participant of a cross-shard transaction, never
    /// locality-scoped: locality decides what a receipt *applies*, and two
    /// committees check each other's copy byte for byte. Which shard
    /// stores an event is the consumer's rule, read off each event's
    /// emitter.
    pub events: Vec<Event>,
    /// Total fuel consumed: engine schedule plus boundary supplement.
    ///
    /// Exact on a completed execution and engine-defined at a core trap,
    /// where wasmtime's in-register counter never flushes and `vm-ref`
    /// charges every executed operator. Reported as the engine saw it
    /// either way; what a consumer needs agreement on is
    /// [`Work`](crate::Work), which is derived beside the receipt rather
    /// than on it.
    pub fuel: u64,
}

/// Why the session refused to produce a receipt.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinishError {
    /// The oracle's verdict: accesses outside the declared set. With
    /// capability materialization in front, this indicates a kernel defect,
    /// and it is checked after every execution regardless.
    #[error("{} accesses outside the declared set", .0.len())]
    Undeclared(Vec<Access>),
    /// A store failure while folding deltas or settling reservations.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The per-transaction kernel session.
#[derive(Debug)]
pub struct KernelSession {
    store: OverlayStore,
    declared: EffectSet,
    table: Vec<Capability>,
    tx: TxHash,
    env: EnvInputs,
    hash_fn: fn(&[u8]) -> [u8; 32],
    locality: Locality,
    /// Materialized interval contents per handle, dropped when a write
    /// touches the collection. A guest walking an interval asks for its
    /// length and then each entry in turn; re-scanning per question makes
    /// that walk quadratic in the interval and floods the access log with
    /// one record per step.
    scans: BTreeMap<u32, Vec<(u128, Vec<u8>)>>,
    /// The distinct entries each write interval has changed, against the
    /// cap that interval declared.
    ///
    /// A scan truncates at the cap, so reads are bounded by construction;
    /// nothing truncates a write, so the budget is counted here or not at
    /// all. Kept per handle rather than per collection because the cap is
    /// a property of the declared interval, and cumulative across the
    /// transaction rather than per scan — a write budget the invalidation
    /// of a materialized interval must not refund.
    written: BTreeMap<u32, BTreeSet<u128>>,
    /// The instance whose method is executing, set by the runner as it
    /// enters each manifest node. The capability table is per transaction
    /// and positional, so the session has no other way to know whose
    /// invocation an emission belongs to.
    invocation: Option<Address>,
    /// Events emitted so far, kept until the outcome is known: an abort
    /// discards them, so nothing an aborted transaction said survives.
    events: Vec<Event>,
    /// Value held on the executing body's behalf, indexed by the rep a
    /// guest's `own<bucket>` handle names.
    ///
    /// Its own rep space, beside the capability table rather than inside
    /// it: a bucket carries value and confers no state access, and a
    /// capability is materialized once from the declaration where a
    /// bucket appears and leaves during execution. A slot empties when
    /// the bucket leaves — dropped by the guest or taken back by the
    /// kernel — and is never reused, so one rep names one bucket for the
    /// transaction's life.
    ///
    /// A bucket is an amount and nothing else. Which resource it is
    /// denominated in is the declaration's answer wherever it is asked —
    /// `outputs` for a produced edge, the cell's own key for a movement —
    /// and the kernel cannot invert a cell key to recover one, so a field
    /// for it would be right in one case and a guess in the rest.
    buckets: Vec<Option<u128>>,
    /// Whether the executing invocation may create value.
    ///
    /// One bit rather than a table of resources. What a grant fixes is
    /// *whether* a body may bring a bucket into existence with no cell
    /// debited behind it; which resource that value is denominated in is
    /// the method's declared outputs' answer, wherever the question is
    /// asked. The bit reaches the guest as a handle all the same, so it
    /// is visible in the export's own type and a body that was granted
    /// nothing has nothing to name.
    issuance: bool,
    /// Reservations already taken, by capability rep.
    ///
    /// A grant answers once. The read this replaces answered every time
    /// it was asked, so a body asking twice held two edges against one
    /// hold; taking is a question with one answer and this is what makes
    /// it so.
    taken: BTreeSet<u32>,
}

impl KernelSession {
    /// Materialize capabilities for a declared effect set over the
    /// overlay's state, judging and holding the declared reservations — or
    /// adopting reservations a batch judge already holds for this
    /// transaction.
    ///
    /// The overlay's base is what locked reads resolve against, fixed
    /// for the whole batch
    /// regardless of what the group threads on top.
    ///
    /// The capability table's order is the effect set's canonical order,
    /// so reps are deterministic; the caller passes handles to the guest
    /// in table order.
    ///
    /// # Errors
    ///
    /// Any [`MaterializeError`]; all are pre-execution aborts.
    pub fn materialize(
        mut store: OverlayStore,
        declared: &EffectSet,
        ordered: &[Effect],
        tx: TxHash,
        env: EnvInputs,
        hash_fn: fn(&[u8]) -> [u8; 32],
    ) -> Result<Self, MaterializeError> {
        store.clear_log();

        // Reservations are judged off the *set*, where `EffectSet::insert`
        // has already summed the amounts two clauses claimed on one cell.
        // Judging the clause list instead would judge each amount
        // separately against the same balance, so a signature reserving
        // `n` twice over a cell holding `n` would pass both.
        let mut reservations = Vec::new();
        for effect in declared.iter() {
            if let (EffectTarget::Point(key), Mode::Reserve { amount }) =
                (effect.target, effect.mode)
            {
                if store.is_locked(key) {
                    return Err(MaterializeError::MutationOfLocked(key));
                }
                match store.held_reservation(key, tx) {
                    Some(held) if held == amount => {}
                    Some(_) => return Err(MaterializeError::HeldMismatch(key)),
                    None => reservations.push((tx, key, amount)),
                }
            }
        }

        // The table is the *clause list*, because a handle's rep is its
        // index here and the guest's parameters are positional. Walking
        // the set instead would order handles by a comparison over
        // hash-derived keys, and would silently shorten the table
        // whenever two clauses evaluated to one target — making a guest's
        // parameter list a function of instance configuration rather than
        // of its own signature.
        let mut table = Vec::with_capacity(ordered.len());
        for effect in ordered {
            table.push(capability_for(&store, *effect)?);
        }
        reject_self_conflicts(declared)?;

        let verdicts = store.judge_and_hold(&reservations)?;
        for ((verdict_tx, key), feasibility) in verdicts {
            if !feasibility.is_feasible() {
                let amount = reservations
                    .iter()
                    .find(|(request_tx, request_key, _)| {
                        *request_tx == verdict_tx && *request_key == key
                    })
                    .map_or(0, |(_, _, amount)| *amount);
                return Err(MaterializeError::Infeasible { key, amount });
            }
        }

        Ok(Self {
            store,
            declared: declared.clone(),
            table,
            tx,
            env,
            hash_fn,
            locality: Locality::All,
            scans: BTreeMap::new(),
            written: BTreeMap::new(),
            invocation: None,
            events: Vec::new(),
            buckets: Vec::new(),
            issuance: false,
            taken: BTreeSet::new(),
        })
    }

    /// Scope the session to the executing shard's keys; see [`Locality`].
    #[must_use]
    pub fn with_locality(mut self, locality: Locality) -> Self {
        self.locality = locality;
        self
    }

    /// The capability table; a handle's rep is its index here.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.table
    }

    /// Takes a quantity into the kernel's keeping, returning the rep a
    /// guest's handle names.
    ///
    /// Every producer is the kernel's own — an edge routed to this
    /// invocation, a debit against a cell the method declared — because
    /// the world exports no constructor for one.
    ///
    /// # Panics
    ///
    /// Only past `u32` buckets in one transaction, which the declared
    /// edge and clause counts exclude.
    pub fn open_bucket(&mut self, amount: u128) -> u32 {
        let rep = u32::try_from(self.buckets.len()).expect("bounded");
        self.buckets.push(Some(amount));
        rep
    }

    /// What the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub fn bucket(&self, rep: u32) -> Result<u128, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.buckets.get(index))
            .copied()
            .flatten()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// Takes the bucket at `rep` back out of the table: the kernel holds
    /// the value again and the rep names nothing afterwards.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub fn take_bucket(&mut self, rep: u32) -> Result<u128, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.buckets.get_mut(index))
            .and_then(Option::take)
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// A bucket handle the guest let go of.
    ///
    /// The canonical ABI delivers the drop and the kernel decides what it
    /// means; that delivery is the whole of what an owned handle buys
    /// over a value a body could simply forget.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub fn drop_bucket(&mut self, rep: u32) -> Result<(), SessionTrap> {
        self.take_bucket(rep).map(|_| ())
    }

    fn capability(&self, rep: u32) -> Result<Capability, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.table.get(index))
            .copied()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// The current value of a declared cell, for the kernel's own gate
    /// reads — the same view a read capability serves, empty meaning
    /// absent. The key comes from the gate admission lowered, which is
    /// the same evaluation that materialized the cell's capability, so
    /// it is declared by construction.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`] the store raises.
    pub fn declared_cell(&mut self, key: SubstateKey) -> Result<Vec<u8>, SessionTrap> {
        Ok(self.store.read(key)?.unwrap_or_default())
    }

    /// Whether a declared holdings interval holds anything, for the
    /// kernel's custody gate — the same view the range capability
    /// serves, over the collection the gate admission lowered names,
    /// which is declared by construction like the gate's cells.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`] the store raises.
    pub fn declared_holdings_non_empty(
        &mut self,
        owner: Address,
        collection: CollectionId,
    ) -> Result<bool, SessionTrap> {
        Ok(!self
            .store
            .entries_in_range(owner, collection, 0, u128::MAX, 1)?
            .is_empty())
    }

    /// A fresh read through a read capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, SessionTrap> {
        match self.capability(rep)? {
            Capability::Read(key) => Ok(self.store.read(key)?.unwrap_or_default()),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// A read through a locked capability: the value comes from
    /// the overlay's base — the attested version — never from state
    /// concurrent transactions are changing.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn locked_cell(&mut self, rep: u32) -> Result<Vec<u8>, SessionTrap> {
        match self.capability(rep)? {
            Capability::Locked(key) => Ok(self.store.locked(key)?.unwrap_or_default()),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The read half of a write capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, SessionTrap> {
        match self.capability(rep)? {
            Capability::Write(key) => Ok(self.store.read(key)?.unwrap_or_default()),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The write half of a write capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), SessionTrap> {
        match self.capability(rep)? {
            Capability::Write(key) => Ok(self.store.write(key, value)?),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// Credit through a delta capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn delta_add(&mut self, rep: u32, amount: u128) -> Result<(), SessionTrap> {
        self.delta(rep, amount, DeltaOp::Add)
    }

    /// Debit through a delta capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn delta_sub(&mut self, rep: u32, amount: u128) -> Result<(), SessionTrap> {
        self.delta(rep, amount, DeltaOp::Sub)
    }

    fn delta(
        &mut self,
        rep: u32,
        amount: u128,
        op: fn(u128) -> DeltaOp,
    ) -> Result<(), SessionTrap> {
        match self.capability(rep)? {
            Capability::Delta(key) => Ok(self.store.queue_delta(key, op(amount))?),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The reserved amount behind a reserve capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn reserve_amount(&mut self, rep: u32) -> Result<u128, SessionTrap> {
        match self.capability(rep)? {
            // The clause's own declared amount, not the folded hold: two
            // reservations on one cell share a single held total, and a
            // guest asking about its grant means its own share of it.
            // The hold is still consulted — a capability whose hold never
            // materialized is a defect whatever amount it declared.
            Capability::Reserve { key, amount } => self
                .store
                .held_reservation(key, self.tx)
                .map(|_| amount)
                .ok_or(SessionTrap::ReservationMissing),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// Debit `amount` through a delta capability and hand the value out
    /// as a bucket.
    ///
    /// The debit is queued like any other, so whether the cell covered it
    /// is the movement fold's question and an over-take is
    /// `Outcome::Infeasible` at settle rather than a refusal here. What
    /// the pairing buys is that the amount debited and the amount now in
    /// flight are one number the body never got to write twice.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn delta_take(&mut self, rep: u32, amount: u128) -> Result<u32, SessionTrap> {
        self.delta(rep, amount, DeltaOp::Sub)?;
        Ok(self.open_bucket(amount))
    }

    /// Credit a delta capability with what the bucket at `funds` carries.
    ///
    /// The bucket is consumed, so the credit and the value that crossed
    /// are one number and there is no second one to disagree with.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn delta_put(&mut self, rep: u32, funds: u32) -> Result<(), SessionTrap> {
        // Nothing is consumed until everything is judged. A refusal
        // aborts the whole transaction, so no state would escape either
        // way; what the ordering keeps true is that the kernel is never
        // holding a credit it did not make, which is the property the
        // bucket table exists to state.
        let Capability::Delta(_) = self.capability(rep)? else {
            return Err(SessionTrap::WrongMode(rep));
        };
        let amount = self.bucket(funds)?;
        self.delta(rep, amount, DeltaOp::Add)?;
        self.take_bucket(funds).map(|_| ())
    }

    /// Credit a write capability's amount cell with what the bucket at
    /// `funds` carries.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_put(&mut self, rep: u32, funds: u32) -> Result<(), SessionTrap> {
        let Capability::Write(key) = self.capability(rep)? else {
            return Err(SessionTrap::WrongMode(rep));
        };
        let held = self.amount_cell(key)?;
        let amount = self.bucket(funds)?;
        let total = held.checked_add(amount).ok_or(SessionTrap::CellOverflow)?;
        self.store.write(key, encode_amount(total).to_vec())?;
        self.take_bucket(funds).map(|_| ())
    }

    /// A declared cell's contents as an amount; an absent cell is zero.
    fn amount_cell(&mut self, key: SubstateKey) -> Result<u128, SessionTrap> {
        let cell = self.store.read(key)?.unwrap_or_default();
        if cell.is_empty() {
            return Ok(0);
        }
        decode_amount(&cell).map_err(|_| SessionTrap::BadAmountCell(key))
    }

    /// Debit `amount` through a write capability and hand the value out
    /// as a bucket.
    ///
    /// The kernel performs the read-modify-write, which is what makes an
    /// absolute cell's value linear too: a body that needs to read a
    /// balance — a curve needs both sides — writes no absolute back, so
    /// there is no number of its own for the edge to disagree with.
    /// Resolved at the call, so the refusals are immediate: a stored cell
    /// that is not an amount, and a debit past what it holds.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_take(&mut self, rep: u32, amount: u128) -> Result<u32, SessionTrap> {
        let Capability::Write(key) = self.capability(rep)? else {
            return Err(SessionTrap::WrongMode(rep));
        };
        let held = self.amount_cell(key)?;
        let left = held.checked_sub(amount).ok_or(SessionTrap::CellUnderflow)?;
        self.store.write(key, encode_amount(left).to_vec())?;
        Ok(self.open_bucket(amount))
    }

    /// Create `amount` of what this invocation issues, as a bucket.
    ///
    /// The one bucket with no cell behind it. `rep` names the grant, of
    /// which an invocation has at most one — the handle's whole content
    /// is that it exists.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a take against a grant this
    /// invocation was never given.
    pub fn issuer_take(&mut self, rep: u32, amount: u128) -> Result<u32, SessionTrap> {
        if rep != ISSUER_REP {
            return Err(SessionTrap::UnknownHandle(rep));
        }
        if !self.issuance {
            return Err(SessionTrap::IssuanceUngranted);
        }
        Ok(self.open_bucket(amount))
    }

    /// Grant the executing invocation the authority to issue.
    ///
    /// Read off the method's own declaration by whoever entered the node;
    /// entering the next one takes it away again.
    pub const fn grant_issuance(&mut self) {
        self.issuance = true;
    }

    /// Take the reservation this capability holds, as a bucket.
    ///
    /// Once per capability: the grant is a quantity the kernel judged and
    /// held before the body ran, and a second answer to the same question
    /// would be a second edge against one hold.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn reserve_take(&mut self, rep: u32) -> Result<u32, SessionTrap> {
        let amount = self.reserve_amount(rep)?;
        if !self.taken.insert(rep) {
            return Err(SessionTrap::ReservationTaken);
        }
        Ok(self.open_bucket(amount))
    }

    fn range_of(
        &self,
        rep: u32,
    ) -> Result<(Address, CollectionId, u128, u128, u32, bool), SessionTrap> {
        match self.capability(rep)? {
            Capability::RangeRead {
                owner,
                collection,
                lo,
                hi,
                cap,
            } => Ok((owner, collection, lo, hi, cap, false)),
            Capability::RangeWrite {
                owner,
                collection,
                lo,
                hi,
                cap,
            } => Ok((owner, collection, lo, hi, cap, true)),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// Materialize the interval behind `rep` if it is not already.
    fn scan(&mut self, rep: u32) -> Result<(), SessionTrap> {
        if self.scans.contains_key(&rep) {
            return Ok(());
        }
        let (owner, collection, lo, hi, cap, _) = self.range_of(rep)?;
        let entries = self
            .store
            .entries_in_range(owner, collection, lo, hi, cap)?;
        self.scans.insert(rep, entries);
        Ok(())
    }

    /// Charge one entry against `rep`'s declared write cap.
    ///
    /// The budget counts distinct orders rather than operations: writing
    /// an entry this interval already changed is the same entry touched
    /// again, and the cap bounds how much of the collection a declaration
    /// reaches, not how many times a guest reaches it.
    fn charge_write(&mut self, rep: u32, order: u128, cap: u32) -> Result<(), SessionTrap> {
        let cap = usize::try_from(cap).unwrap_or(usize::MAX);
        let written = self.written.entry(rep).or_default();
        if !written.contains(&order) && written.len() >= cap {
            return Err(SessionTrap::WriteCapExceeded {
                cap: u32::try_from(cap).unwrap_or(u32::MAX),
                order,
            });
        }
        written.insert(order);
        Ok(())
    }

    /// Drop every materialized interval over a collection a write touched.
    fn invalidate(&mut self, owner: Address, collection: CollectionId) {
        let stale: Vec<u32> = self
            .scans
            .keys()
            .copied()
            .filter(|rep| {
                self.range_of(*rep)
                    .is_ok_and(|(scanned_owner, scanned_collection, ..)| {
                        scanned_owner == owner && scanned_collection == collection
                    })
            })
            .collect();
        for rep in stale {
            self.scans.remove(&rep);
        }
    }

    /// Entries currently visible in the interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_count(&mut self, rep: u32) -> Result<u32, SessionTrap> {
        self.scan(rep)?;
        Ok(u32::try_from(self.scans[&rep].len()).unwrap_or(u32::MAX))
    }

    /// The order key at `index`, ascending.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_order(&mut self, rep: u32, index: u32) -> Result<u128, SessionTrap> {
        self.scan(rep)?;
        indexed(&self.scans[&rep], index).map(|(order, _)| *order)
    }

    /// The entry value at `index`, ascending.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, SessionTrap> {
        self.scan(rep)?;
        indexed(&self.scans[&rep], index).map(|(_, value)| value.clone())
    }

    /// Replace the entry value at `index` through a write interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), SessionTrap> {
        let (owner, collection, _, _, cap, writable) = self.range_of(rep)?;
        if !writable {
            return Err(SessionTrap::WrongMode(rep));
        }
        self.scan(rep)?;
        let order = *indexed(&self.scans[&rep], index).map(|(order, _)| order)?;
        self.charge_write(rep, order, cap)?;
        self.store.entry_write(owner, collection, order, value)?;
        self.invalidate(owner, collection);
        Ok(())
    }

    /// Insert or replace the entry at `order`, which must lie inside the
    /// declared interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_insert(
        &mut self,
        rep: u32,
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), SessionTrap> {
        let (owner, collection, lo, hi, cap, writable) = self.range_of(rep)?;
        if !writable {
            return Err(SessionTrap::WrongMode(rep));
        }
        if !(lo..=hi).contains(&order) {
            return Err(SessionTrap::OrderOutsideInterval);
        }
        self.charge_write(rep, order, cap)?;
        self.store.entry_write(owner, collection, order, value)?;
        self.invalidate(owner, collection);
        Ok(())
    }

    /// Remove the entry at `index` through a write interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), SessionTrap> {
        let (owner, collection, _, _, cap, writable) = self.range_of(rep)?;
        if !writable {
            return Err(SessionTrap::WrongMode(rep));
        }
        self.scan(rep)?;
        let order = *indexed(&self.scans[&rep], index).map(|(order, _)| order)?;
        self.charge_write(rep, order, cap)?;
        self.store.entry_remove(owner, collection, order)?;
        self.invalidate(owner, collection);
        Ok(())
    }

    /// The transaction clock in milliseconds.
    #[must_use]
    pub const fn clock_ms(&self) -> u64 {
        self.env.clock_ms
    }

    /// The transaction's randomness draw.
    #[must_use]
    pub const fn randomness(&self) -> [u8; 32] {
        self.env.randomness
    }

    /// The protocol hash function.
    #[must_use]
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        (self.hash_fn)(data)
    }

    /// Enter an invocation: subsequent emissions are stamped with
    /// `emitter`, the address of the instance whose method runs next.
    ///
    /// The runner calls this as it walks each manifest node, since the
    /// node names its target and the session does not.
    pub const fn enter_invocation(&mut self, emitter: Address) {
        self.invocation = Some(emitter);
        // Issuance is one node's, granted from that node's own
        // declaration, so entering the next one starts from nothing.
        self.issuance = false;
    }

    /// Leave the current invocation. An emission outside one is a runner
    /// defect and traps rather than guessing an emitter.
    pub const fn leave_invocation(&mut self) {
        self.invocation = None;
        self.issuance = false;
    }

    /// Emit an event from the executing instance.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`]: no invocation to attribute it to, a type past
    /// [`MAX_EVENT_TYPES`], or a count or payload past its cap. The caps
    /// trap rather than truncate, so what a transaction emitted is either
    /// entirely in its receipt or the transaction did not complete.
    pub fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), SessionTrap> {
        let emitter = self.invocation.ok_or(SessionTrap::NoInvocation)?;
        if event_type >= MAX_EVENT_TYPES {
            return Err(SessionTrap::EventTypeOutOfRange(event_type));
        }
        if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(SessionTrap::EventPayloadTooLarge(payload.len()));
        }
        if self.events.len() >= MAX_EVENTS_PER_TX {
            return Err(SessionTrap::TooManyEvents);
        }
        self.events.push(Event {
            emitter,
            event_type,
            payload,
        });
        Ok(())
    }

    /// Settle every reservation the table holds: an owned cell's settle
    /// releases the hold and folds the debit, a remote one releases with
    /// the amount kept as the outbound record. The store's hold is the
    /// per-transaction fold, so a cell reserved by several clauses
    /// settles once, whole — a second settle of the same hold would find
    /// it already gone.
    ///
    /// The outer error is a kernel defect; the inner `Err` is the
    /// refusal the caller aborts the transaction with.
    #[allow(clippy::type_complexity)] // verdict-or-defect, both fallible
    fn settle_reservations(
        &mut self,
    ) -> Result<Result<BTreeMap<SubstateKey, u128>, Outcome>, FinishError> {
        let mut settles = BTreeMap::new();
        for capability in &self.table.clone() {
            if let Capability::Reserve { key, .. } = capability {
                if settles.contains_key(key) {
                    continue;
                }
                // A remote reservation settles at its owning shard; here
                // the hold releases and the receipt keeps the amount as
                // the outbound record.
                let settled = if self.locality.is_local(key.owner) {
                    self.store.settle(*key, self.tx)
                } else {
                    self.store.release(*key, self.tx)
                };
                match settled {
                    Ok(amount) => {
                        settles.insert(*key, amount);
                    }
                    // An exclusive write earlier in this group drained the
                    // cell below the reservation it still covers. The
                    // reserver lost that race, and the refusal left its
                    // hold standing, so the amount is still readable.
                    Err(StoreError::HeldExceedsCommitted(_)) => {
                        let amount = self
                            .store
                            .held_reservation(*key, self.tx)
                            .unwrap_or_default();
                        return Ok(Err(Outcome::Infeasible { key: *key, amount }));
                    }
                    Err(defect) => match declaration_defect(&defect) {
                        Some(outcome) => return Ok(Err(outcome)),
                        None => return Err(defect.into()),
                    },
                }
            }
        }
        Ok(Ok(settles))
    }

    /// Close the session: fold queued deltas, settle this transaction's
    /// reservations, run the trace-subset oracle, and produce the receipt
    /// together with the threaded store (the input for the next
    /// transaction in a conflict group).
    ///
    /// A debit past the movement floor — committed plus this
    /// transaction's credit, minus every outstanding reservation — is the
    /// transaction's own deterministic loss: it comes back as an
    /// [`Outcome::Infeasible`] receipt over the untouched store, never as
    /// an error.
    ///
    /// Supply accumulators do not move here, and cannot: a movement lands
    /// on a hashed key, so the resource it moved is unknowable at this
    /// layer — see [`SupplyLedger`](crate::SupplyLedger) for where the
    /// accumulator does move.
    ///
    /// # Errors
    ///
    /// [`FinishError::Undeclared`] if any recorded access escaped the
    /// declared set; a store failure otherwise. All are kernel defects.
    pub fn finish(
        mut self,
        outcome: Outcome,
        fuel: u64,
    ) -> Result<(Receipt, OverlayStore), FinishError> {
        // Movements first: the pending deltas, as checked totals.
        let mut movements: BTreeMap<SubstateKey, Movement> = BTreeMap::new();
        let queued: Vec<(SubstateKey, Vec<DeltaOp>)> = self.store.pending_deltas().collect();
        for (key, ops) in queued {
            match total_movement(&ops) {
                Ok(movement) => {
                    movements.insert(key, movement);
                }
                // Totals past `u128` are the guest's own arithmetic — it
                // queued the operations — so the loss is its own.
                Err(error) => {
                    return Ok(abort_with(
                        self.store,
                        Outcome::UserError {
                            reason: error.into(),
                        },
                        fuel,
                    ));
                }
            }
        }
        for (key, movement) in &movements {
            if !self.locality.is_local(key.owner) {
                // The owning shard judges its own cells; here the
                // movement is the outbound record.
                continue;
            }
            let refusal = match self
                .store
                .judge_movement(*key, movement.credit, movement.debit)
            {
                Ok(_) => continue,
                // An uncovered debit, and a cell an exclusive write left
                // below the reservations still outstanding on it, are the
                // same deterministic loss: the floor this movement needed
                // is not there, and the transaction that declared the
                // movement is the one that loses.
                Err(
                    StoreError::Mode(ModeError::CellUnderflow | ModeError::CellOverflow)
                    | StoreError::HeldExceedsCommitted(_),
                ) => Outcome::Infeasible {
                    key: *key,
                    amount: movement.debit,
                },
                Err(defect) => match declaration_defect(&defect) {
                    Some(outcome) => outcome,
                    None => return Err(defect.into()),
                },
            };
            return Ok(abort_with(self.store, refusal, fuel));
        }
        // A movement on a key this shard does not own folds at the owning
        // shard, never here: the receipt already carries it as the
        // outbound record, and folding it locally would fabricate a
        // balance for a cell this shard holds none of.
        let locality = self.locality.clone();
        self.store
            .retain_pending_deltas(&|key: SubstateKey| locality.is_local(key.owner));
        if let Err(defect) = self.store.commit_deltas() {
            // Every remaining fold is on an owned cell the movement judge
            // just cleared, so anything but a declaration defect here is
            // the kernel's.
            return match declaration_defect(&defect) {
                Some(outcome) => Ok(abort_with(self.store, outcome, fuel)),
                None => Err(defect.into()),
            };
        }
        let settles = match self.settle_reservations()? {
            Ok(settles) => settles,
            Err(refusal) => return Ok(abort_with(self.store, refusal, fuel)),
        };
        let escaped = undeclared_accesses(self.store.access_log(), &self.declared);
        if !escaped.is_empty() {
            return Err(FinishError::Undeclared(escaped));
        }
        let mut delta = diff(&self.store);
        // Commutative changes report as movements, never as absolutes.
        delta
            .cells
            .retain(|key, _| !movements.contains_key(key) && !settles.contains_key(key));
        delta.movements = movements.into();
        delta.settles = settles.into();
        self.store.merge_active();
        Ok((
            Receipt {
                outcome,
                delta,
                events: self.events,
                fuel,
            },
            self.store,
        ))
    }

    /// Abandon the session: the transaction's layer is dropped and the
    /// store returns as the session found it.
    #[must_use]
    pub fn discard(mut self) -> OverlayStore {
        self.store.discard_active();
        self.store
    }

    /// The session's store, for test inspection.
    #[must_use]
    pub const fn store(&self) -> &OverlayStore {
        &self.store
    }
}

/// One cell's credit and debit totals over this transaction's queued
/// deltas.
///
/// # Errors
///
/// [`ModeError::DeltaOverflow`] if either total leaves `u128`.
fn total_movement(ops: &[DeltaOp]) -> Result<Movement, ModeError> {
    let mut movement = Movement::default();
    for op in ops {
        match op {
            DeltaOp::Add(amount) => {
                movement.credit = movement
                    .credit
                    .checked_add(*amount)
                    .ok_or(ModeError::DeltaOverflow)?;
            }
            DeltaOp::Sub(amount) => {
                movement.debit = movement
                    .debit
                    .checked_add(*amount)
                    .ok_or(ModeError::DeltaOverflow)?;
            }
        }
    }
    Ok(movement)
}

/// Abandon everything this transaction did and report the failure as its
/// own rather than the batch's.
fn abort_with(mut store: OverlayStore, outcome: Outcome, fuel: u64) -> (Receipt, OverlayStore) {
    store.discard_active();
    (
        Receipt {
            outcome,
            delta: StateDelta::default(),
            // An abort discards its effects, and what it claimed happened
            // is one of them.
            events: Vec::new(),
            fuel,
        },
        store,
    )
}

/// Whether a store refusal belongs to the transaction that provoked it.
///
/// A cell that is not an amount cell is the one such refusal: something
/// holding an exclusive write put other bytes there, and a commutative
/// mode declared over it cannot fold. That is the declaring transaction's
/// defect — the same verdict an unusable reserve target gets — and the
/// batch carries on without it. Every other store refusal is a kernel
/// defect and stops the batch.
fn declaration_defect(defect: &StoreError) -> Option<Outcome> {
    match defect {
        StoreError::Mode(error @ ModeError::BadAmountCell(_)) => Some(Outcome::UserError {
            reason: (*error).into(),
        }),
        _ => None,
    }
}

/// One transaction may not declare both an exclusive write and a
/// commutative mode on the same cell: the receipt records absolutes for
/// the one and movements for the other, and they cannot compose.
fn reject_self_conflicts(declared: &EffectSet) -> Result<(), MaterializeError> {
    let effects: Vec<Effect> = declared.iter().collect();
    for (index, a) in effects.iter().enumerate() {
        for b in &effects[index + 1..] {
            if let (EffectTarget::Point(key), EffectTarget::Point(other)) = (a.target, b.target)
                && key == other
            {
                let kinds = (a.mode.kind(), b.mode.kind());
                let exclusive_and_commutative = matches!(
                    kinds,
                    (ModeKind::Write, ModeKind::Delta | ModeKind::Reserve)
                        | (ModeKind::Delta | ModeKind::Reserve, ModeKind::Write)
                );
                if exclusive_and_commutative {
                    return Err(MaterializeError::SelfConflicting(key));
                }
            }
        }
    }
    Ok(())
}

/// The capability form of one declared effect: the world-design mapping.
/// Entry targets are degenerate one-entry intervals, so collection access
/// needs exactly two resource shapes.
fn capability_for(store: &OverlayStore, effect: Effect) -> Result<Capability, MaterializeError> {
    let locked_checked = |key: SubstateKey| {
        if store.is_locked(key) {
            Err(MaterializeError::MutationOfLocked(key))
        } else {
            Ok(key)
        }
    };
    match (effect.target, effect.mode) {
        (EffectTarget::Point(key), Mode::Read) => Ok(Capability::Read(key)),
        // The mirror of `locked_checked`, and the reason a locked read needs
        // no proof: an unlocked target could differ between the shard that
        // owns it and one that only reads it, and a locked read makes no
        // participant, so nothing would carry the owner's value to anyone
        // else. Two participants would read one key and derive two
        // receipts. A read of mutable state is `Mode::Read`, which
        // provisions.
        (EffectTarget::Point(key), Mode::Locked) => {
            if store.is_locked(key) {
                Ok(Capability::Locked(key))
            } else {
                Err(MaterializeError::UnlockedTarget(key))
            }
        }
        (EffectTarget::Point(key), Mode::Write) => Ok(Capability::Write(locked_checked(key)?)),
        (EffectTarget::Point(key), Mode::Delta) => Ok(Capability::Delta(locked_checked(key)?)),
        (EffectTarget::Point(key), Mode::Reserve { amount }) => Ok(Capability::Reserve {
            key: locked_checked(key)?,
            amount,
        }),
        (
            EffectTarget::Entry {
                owner,
                collection,
                order,
            },
            Mode::Read,
        ) => Ok(Capability::RangeRead {
            owner,
            collection,
            lo: order,
            hi: order,
            cap: 1,
        }),
        (
            EffectTarget::Entry {
                owner,
                collection,
                order,
            },
            Mode::Write,
        ) => Ok(Capability::RangeWrite {
            owner,
            collection,
            lo: order,
            hi: order,
            cap: 1,
        }),
        (
            EffectTarget::Range {
                owner,
                collection,
                lo,
                hi,
                cap,
            },
            Mode::Read,
        ) => Ok(Capability::RangeRead {
            owner,
            collection,
            lo,
            hi,
            cap,
        }),
        (
            EffectTarget::Range {
                owner,
                collection,
                lo,
                hi,
                cap,
            },
            Mode::Write,
        ) => Ok(Capability::RangeWrite {
            owner,
            collection,
            lo,
            hi,
            cap,
        }),
        _ => Err(MaterializeError::Unsupported(Box::new(effect))),
    }
}

fn indexed<T>(entries: &[T], index: u32) -> Result<&T, SessionTrap> {
    usize::try_from(index)
        .ok()
        .and_then(|index| entries.get(index))
        .ok_or(SessionTrap::IndexOutOfBounds {
            index,
            count: entries.len(),
        })
}

/// The committed state change: the active layer against what the store
/// held before this transaction — a write of the value already in place
/// is no change at all.
fn diff(store: &OverlayStore) -> StateDelta {
    let mut delta = StateDelta::default();
    for (key, after) in store.active_cells() {
        if store.pre_active_cell(key).as_deref() != after {
            delta.cells.insert(key, after.map(<[u8]>::to_vec));
        }
    }
    for (key, after) in store.active_entries() {
        if store
            .pre_active_entry(key.owner, key.collection, key.order)
            .as_deref()
            != after
        {
            delta.entries.insert(key, after.map(<[u8]>::to_vec));
        }
    }
    delta
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_vm_effects::{
        Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, Hash32, Mode, RoleId,
        SubstateKey, TestHasher, child_key,
    };

    use super::{
        Capability, EnvInputs, Event, KernelSession, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES,
        MAX_EVENTS_PER_TX, MaterializeError, Outcome, SessionTrap,
    };
    use crate::modes::{TxHash, encode_amount};
    use crate::overlay::OverlayStore;
    use crate::store::{MemoryStore, StoreError, WorkingStore};

    fn key(byte: u8) -> SubstateKey {
        child_key(
            &TestHasher,
            Address::new([byte; 31], AddressClass::Component),
            RoleId(1),
            &[],
        )
    }

    const fn tx(byte: u8) -> TxHash {
        TxHash(Hash32([byte; 32]))
    }

    /// A stand-in protocol hash: the length in the first byte is enough
    /// to show the seam carries the guest's bytes through.
    fn hash(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = u8::try_from(data.len()).unwrap_or(u8::MAX);
        out
    }

    const fn env() -> EnvInputs {
        EnvInputs {
            clock_ms: 5,
            randomness: [3; 32],
        }
    }

    fn declared(effects: &[Effect]) -> EffectSet {
        let mut set = EffectSet::new();
        for effect in effects {
            set.insert(*effect).unwrap();
        }
        set
    }

    /// Canonical order as the clause order — right for tests that build a
    /// set directly and have no signature to evaluate.
    fn ord(set: &EffectSet) -> Vec<Effect> {
        set.iter().collect()
    }

    #[test]
    fn the_table_follows_the_clause_order_not_the_set_order() {
        // A handle's rep is its index here and a guest's parameters are
        // positional, so the table must be the order the author wrote —
        // never the set's, which is a comparison over hash-derived keys.
        let (first, second) = (key(0xA1), key(0xA2));
        let write = |k| Effect {
            target: EffectTarget::Point(k),
            mode: Mode::Write,
        };
        let set = declared(&[write(first), write(second)]);

        // Whichever way canonical order happens to fall, the reverse of it
        // is a clause order the table has to reproduce exactly.
        let mut reversed: Vec<Effect> = set.iter().collect();
        reversed.reverse();
        let session = KernelSession::materialize(
            OverlayStore::new(Arc::new(MemoryStore::new())),
            &set,
            &reversed,
            tx(1),
            env(),
            hash,
        )
        .expect("two ordinary writes materialize");

        let expected: Vec<Capability> = reversed
            .iter()
            .map(|effect| match effect.target {
                EffectTarget::Point(k) => Capability::Write(k),
                other => panic!("unexpected target {other:?}"),
            })
            .collect();
        assert_eq!(session.capabilities(), expected);
    }

    #[test]
    fn coincident_clauses_each_get_a_handle() {
        // Two clauses that evaluate to one target fold to a single set
        // entry — a degenerate instance configuration does exactly this.
        // The guest's parameter list is a function of its signature, not
        // of that configuration, so the table keeps both slots.
        let cell = key(0xB4);
        let write = Effect {
            target: EffectTarget::Point(cell),
            mode: Mode::Write,
        };
        let set = declared(&[write, write]);
        assert_eq!(set.len(), 1, "the set folds them");

        let session = KernelSession::materialize(
            OverlayStore::new(Arc::new(MemoryStore::new())),
            &set,
            &[write, write],
            tx(1),
            env(),
            hash,
        )
        .expect("a repeated write is not a self-conflict");
        assert_eq!(
            session.capabilities(),
            [Capability::Write(cell), Capability::Write(cell)],
            "one handle per clause"
        );
    }

    #[test]
    fn repeated_reservations_are_judged_against_their_sum() {
        // The reason materialization keeps both views. Judging the clause
        // list would weigh each amount against the same balance
        // separately, so a signature reserving 60 twice over a cell
        // holding 100 would pass both and hold 120.
        let vault = key(0xC7);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();
        store.clear_log();

        let reserve = Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Reserve { amount: 60 },
        };
        let set = declared(&[reserve, reserve]);

        let refused = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &set,
            &[reserve, reserve],
            tx(1),
            env(),
            hash,
        )
        .expect_err("120 reserved against 100 is infeasible");
        assert_eq!(
            refused,
            MaterializeError::Infeasible {
                key: vault,
                amount: 120,
            },
            "the folded amount is judged, not each clause's"
        );
    }

    #[test]
    fn repeated_reservations_grant_each_clause_its_own_amount() {
        // The folded hold covers the sum, but each clause's grant is its
        // own declared share — a guest moving exactly what its clause
        // asked for checks against that share, not the fold. Handing
        // every clause the folded total would trap the second withdraw
        // of any fan-out.
        let vault = key(0xC8);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();
        store.clear_log();

        let reserve = |amount| Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Reserve { amount },
        };
        let mut session = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &declared(&[reserve(5), reserve(6)]),
            &[reserve(5), reserve(6)],
            tx(1),
            env(),
            hash,
        )
        .expect("11 reserved against 100 is feasible");

        assert_eq!(session.reserve_amount(0), Ok(5));
        assert_eq!(session.reserve_amount(1), Ok(6));
    }

    fn session_over(store: MemoryStore, set: &EffectSet) -> KernelSession {
        KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            set,
            &ord(set),
            tx(1),
            env(),
            hash,
        )
        .expect("materializes")
    }

    #[test]
    fn a_rep_outside_the_table_is_an_unknown_handle() {
        let set = declared(&[Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Read,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        assert_eq!(session.read_cell(7), Err(SessionTrap::UnknownHandle(7)));
        assert_eq!(session.range_count(7), Err(SessionTrap::UnknownHandle(7)));
    }

    #[test]
    fn a_capability_grants_only_its_own_operation() {
        let set = declared(&[Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Read,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        // A read handle is not a locked read, a write, a delta, a reserve, or
        // an interval.
        assert_eq!(session.locked_cell(0), Err(SessionTrap::WrongMode(0)));
        assert_eq!(session.write_cell_get(0), Err(SessionTrap::WrongMode(0)));
        assert_eq!(
            session.write_cell_set(0, vec![1]),
            Err(SessionTrap::WrongMode(0))
        );
        assert_eq!(session.delta_add(0, 1), Err(SessionTrap::WrongMode(0)));
        assert_eq!(session.reserve_amount(0), Err(SessionTrap::WrongMode(0)));
        assert_eq!(session.range_count(0), Err(SessionTrap::WrongMode(0)));
    }

    #[test]
    fn interval_operations_bound_their_index_and_order() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        store.entry_write(owner, collection, 10, vec![1]).unwrap();
        store.clear_log();
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 5,
                hi: 15,
                cap: 4,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(store, &set);

        assert_eq!(session.range_count(0), Ok(1));
        assert_eq!(session.range_entry(0, 0), Ok(vec![1]));
        assert_eq!(
            session.range_entry(0, 1),
            Err(SessionTrap::IndexOutOfBounds { index: 1, count: 1 })
        );
        assert_eq!(
            session.range_remove(0, 9),
            Err(SessionTrap::IndexOutOfBounds { index: 9, count: 1 })
        );
        // An insert must land inside the declared interval, and its order
        // key is an amount cell like any other.
        assert_eq!(
            session.range_insert(0, 99, vec![2]),
            Err(SessionTrap::OrderOutsideInterval)
        );
        assert_eq!(session.range_insert(0, 12, vec![2]), Ok(()));
        assert_eq!(session.range_count(0), Ok(2));
    }

    #[test]
    fn a_write_interval_bounds_the_entries_it_adds_by_its_cap() {
        // Nothing truncates a write the way a scan truncates a read, so
        // the cap has to refuse: a declaration claiming two entries must
        // not be able to grow the collection without bound.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 2,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);

        assert_eq!(session.range_insert(0, 10, vec![1]), Ok(()));
        assert_eq!(session.range_insert(0, 20, vec![2]), Ok(()));
        assert_eq!(
            session.range_insert(0, 30, vec![3]),
            Err(SessionTrap::WriteCapExceeded { cap: 2, order: 30 }),
            "a third distinct entry is past the declared cap"
        );

        // Rewriting an entry the interval already changed is the same
        // entry touched again, not a new one.
        assert_eq!(session.range_insert(0, 10, vec![9]), Ok(()));
    }

    #[test]
    fn the_write_budget_survives_a_scan_invalidation() {
        // A write drops the materialized interval, and the budget must not
        // come back with it — otherwise re-scanning between writes buys an
        // unbounded number of them.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 1,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);

        assert_eq!(session.range_insert(0, 10, vec![1]), Ok(()));
        assert_eq!(
            session.range_count(0),
            Ok(1),
            "re-materializes the interval"
        );
        assert_eq!(
            session.range_insert(0, 20, vec![2]),
            Err(SessionTrap::WriteCapExceeded { cap: 1, order: 20 }),
        );
    }

    #[test]
    fn a_full_page_of_read_modify_writes_fits_its_cap() {
        // The order book's fill: scan the cap and rewrite or remove every
        // entry it returned. The write budget is the cap, and reads are
        // truncated at it separately, so the pattern sits exactly inside
        // the declaration rather than being refused by it.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..4u128 {
            store
                .entry_write(owner, collection, order, vec![u8::try_from(order).unwrap()])
                .unwrap();
        }
        store.clear_log();
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(store, &set);

        assert_eq!(session.range_count(0), Ok(4));
        for index in 0..4 {
            assert_eq!(session.range_set(0, index, vec![0xFF]), Ok(()));
        }
        // And removing what it just rewrote reaches no new entry.
        assert_eq!(session.range_remove(0, 0), Ok(()));
    }

    #[test]
    fn a_read_interval_refuses_every_mutation() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: 10,
                cap: 4,
            },
            mode: Mode::Read,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        assert_eq!(
            session.range_set(0, 0, vec![1]),
            Err(SessionTrap::WrongMode(0))
        );
        assert_eq!(
            session.range_insert(0, 1, vec![1]),
            Err(SessionTrap::WrongMode(0))
        );
        assert_eq!(session.range_remove(0, 0), Err(SessionTrap::WrongMode(0)));
    }

    #[test]
    fn one_transaction_cannot_hold_both_absolute_and_commutative_modes() {
        let cell = key(3);
        let set = declared(&[
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Write,
            },
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Delta,
            },
        ]);
        assert_eq!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &set,
                &ord(&set),
                tx(1),
                env(),
                hash,
            )
            .expect_err("absolute and movement semantics cannot compose"),
            MaterializeError::SelfConflicting(cell)
        );
    }

    #[test]
    fn a_mismatched_held_reservation_is_surfaced_not_adopted() {
        let vault = key(4);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();
        // A batch judge already holds a different amount for this
        // transaction than the declaration asks for.
        store.judge_and_hold(&[(tx(1), vault, 40)]).unwrap();
        store.clear_log();
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Reserve { amount: 50 },
        }]);
        assert_eq!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(store)),
                &set,
                &ord(&set),
                tx(1),
                env(),
                hash,
            )
            .expect_err("a bookkeeping mismatch is a defect, not an adoption"),
            MaterializeError::HeldMismatch(vault)
        );
    }

    #[test]
    fn a_mode_the_world_cannot_hand_out_refuses_at_materialization() {
        // A locked read of a collection interval has no capability form.
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner: Address::new([9; 31], AddressClass::Component),
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: 1,
                cap: 1,
            },
            mode: Mode::Locked,
        }]);
        assert!(matches!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &set,
                &ord(&set),
                tx(1),
                env(),
                hash,
            ),
            Err(MaterializeError::Unsupported(_))
        ));
    }

    #[test]
    fn the_environment_reaches_the_guest_unchanged() {
        let session = session_over(MemoryStore::new(), &EffectSet::new());
        assert_eq!(session.clock_ms(), env().clock_ms);
        assert_eq!(session.randomness(), env().randomness);
        assert_eq!(session.hash(&[1, 2, 3])[0], 3);
        assert!(session.capabilities().is_empty());
    }

    #[test]
    fn an_emission_is_stamped_with_the_entered_invocation() {
        // Attribution decides which shard stores an event, so the address
        // comes from the runner entering a node — never from the guest,
        // which would make it a claim.
        let mut session = session_over(MemoryStore::new(), &EffectSet::new());
        let (first, second) = (
            Address::new([0x11; 31], AddressClass::Component),
            Address::new([0x22; 31], AddressClass::Component),
        );

        session.enter_invocation(first);
        session.emit(3, b"one".to_vec()).unwrap();
        session.enter_invocation(second);
        session.emit(4, b"two".to_vec()).unwrap();

        let (receipt, _) = session
            .finish(Outcome::Completed { value: None }, 0)
            .unwrap();
        assert_eq!(
            receipt.events,
            vec![
                Event {
                    emitter: first,
                    event_type: 3,
                    payload: b"one".to_vec(),
                },
                Event {
                    emitter: second,
                    event_type: 4,
                    payload: b"two".to_vec(),
                },
            ],
        );
    }

    #[test]
    fn emission_refuses_outside_an_invocation_and_past_its_caps() {
        let mut session = session_over(MemoryStore::new(), &EffectSet::new());
        assert_eq!(session.emit(0, Vec::new()), Err(SessionTrap::NoInvocation));

        session.enter_invocation(Address::new([7; 31], AddressClass::Component));
        assert_eq!(
            session.emit(MAX_EVENT_TYPES, Vec::new()),
            Err(SessionTrap::EventTypeOutOfRange(MAX_EVENT_TYPES)),
        );
        let oversized = vec![0u8; MAX_EVENT_PAYLOAD_BYTES + 1];
        assert_eq!(
            session.emit(0, oversized),
            Err(SessionTrap::EventPayloadTooLarge(
                MAX_EVENT_PAYLOAD_BYTES + 1
            )),
        );
        for _ in 0..MAX_EVENTS_PER_TX {
            session.emit(0, Vec::new()).unwrap();
        }
        // The cap traps rather than truncating: what a transaction emitted
        // is entirely in its receipt, or the transaction did not complete.
        assert_eq!(session.emit(0, Vec::new()), Err(SessionTrap::TooManyEvents));

        session.leave_invocation();
        assert_eq!(session.emit(0, Vec::new()), Err(SessionTrap::NoInvocation));
    }

    #[test]
    fn an_abort_discards_what_the_transaction_claimed() {
        // An abort discards its effects, and a claim about what happened
        // is one of them.
        let cell = key(0xE1);
        let set = declared(&[Effect {
            target: EffectTarget::Point(cell),
            mode: Mode::Delta,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);

        session.enter_invocation(Address::new([9; 31], AddressClass::Component));
        session.emit(1, b"paid".to_vec()).unwrap();
        session.delta_sub(0, 1).unwrap();

        let (receipt, _) = session
            .finish(Outcome::Completed { value: None }, 7)
            .unwrap();
        assert!(
            matches!(receipt.outcome, Outcome::Infeasible { .. }),
            "a debit past the floor is the transaction's own loss",
        );
        assert!(receipt.events.is_empty());
    }

    #[test]
    fn judging_refuses_the_same_pair_twice() {
        let vault = key(5);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();
        assert_eq!(
            store.judge_and_hold(&[(tx(1), vault, 10), (tx(1), vault, 20)]),
            Err(StoreError::DuplicateRequest {
                tx: tx(1),
                key: vault,
            })
        );
        let mut overlay = OverlayStore::new(Arc::new(store));
        assert_eq!(
            overlay.judge_and_hold(&[(tx(1), vault, 10), (tx(1), vault, 20)]),
            Err(StoreError::DuplicateRequest {
                tx: tx(1),
                key: vault,
            })
        );
    }
}
