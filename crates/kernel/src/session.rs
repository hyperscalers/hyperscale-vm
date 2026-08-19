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
    ABSENT_REP, AbortReason, Address, CollectionId, Effect, EffectSet, EffectTarget, EntryKey,
    ISSUER_REP, Mode, Presence, SubstateKey, distinct_ids,
};
use hyperscale_vm_embed::math::{MathError, Rounding, U256, mul_div};

use crate::ledger::AmountLedger;
use crate::locality::Locality;
use crate::modes::{AMOUNT_CELL_BYTES, DeltaOp, ModeError, TxHash, decode_amount, encode_amount};
use crate::oracle::undeclared_accesses;
use crate::overlay::OverlayStore;
use crate::store::{Access, StoreError, WorkingStore};
use crate::supply::SupplyDelta;

/// The ordered-collection interval a range handle names.
///
/// The two range capabilities carry this and differ only in what they
/// permit, which leaves the mode where it belongs — in whether the
/// handle resolves at all, rather than in a second copy of the bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    /// The collection's owner.
    pub owner: Address,
    /// The collection's identity under the owner.
    pub collection: CollectionId,
    /// Inclusive lower order-key bound.
    pub lo: u128,
    /// Inclusive upper order-key bound.
    pub hi: u128,
    /// The declared entry cap: a scan truncates at it, and it bounds the
    /// distinct entries a write interval may change — separately, since a
    /// read-modify-write reaches its whole page and an insert adds
    /// entries no scan returned.
    pub cap: u32,
}

impl Interval {
    /// Whether `order` falls inside the declared bounds.
    #[must_use]
    pub const fn holds(&self, order: u128) -> bool {
        self.lo <= order && order <= self.hi
    }
}

/// One materialized capability: what a handle rep grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// A fresh read of one cell.
    Read(SubstateKey),
    /// A pinned read of one cell.
    Locked(SubstateKey),
    /// An exclusive read-modify-write of one cell holding bytes.
    Write(SubstateKey),
    /// The same exclusive access to a cell holding value.
    ///
    /// A separate variant rather than a flag, because the two share no
    /// operation: bytes are read and replaced, value is credited and
    /// debited, and a handle that offered both would be one the kernel
    /// had to refuse half of at every call.
    Amount(SubstateKey),
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
    RangeRead(Interval),
    /// A read-modify-write interval of an ordered collection whose
    /// entries are the package's own bytes.
    RangeWrite(Interval),
    /// The same interval over entries that are instances of one
    /// resource, on the terms [`Capability::Amount`] states.
    InstanceRange(Interval),
}

/// What a bucket carries.
///
/// The two are one object because they are one thing to a manifest — value
/// in flight between a producer and a consumer — and they differ in what
/// quantity means: a fungible edge has an amount nothing declares, and a
/// non-fungible one names the instances it moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Held {
    /// A quantity of a fungible resource.
    Amount(u128),
    /// The instances a non-fungible edge moves, by the order key each was
    /// filed at in its collection.
    Instances(BTreeSet<u128>),
}

impl Held {
    /// What a signed bound is judged over: an amount, or how many
    /// instances.
    ///
    /// # Panics
    ///
    /// Never: an instance set is bounded by the per-edge cap, well below
    /// `u128`.
    #[must_use]
    pub fn quantity(&self) -> u128 {
        match self {
            Self::Amount(amount) => *amount,
            Self::Instances(ids) => u128::try_from(ids.len()).expect("bounded by the edge cap"),
        }
    }

    /// Whether it carries nothing, which is what a bucket must for a
    /// guest to let go of it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.quantity() == 0
    }
}

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
    /// A write requiring the leaf absent, on a target the store holds.
    ///
    /// The same class of verdict as an infeasible reservation, and at
    /// the same seam: a precondition on committed state, judged by the
    /// shard that holds the leaf, before any body observes anything.
    /// Carries the target rather than a key, because the two shapes that
    /// name one leaf are a cell and a collection entry, and only one of
    /// them is a key.
    #[error("a write requiring an absent leaf lands on occupied {0:?}")]
    Occupied(EffectTarget),
    /// A write requiring the leaf there, on a target the store does not
    /// hold.
    #[error("a write requiring a present leaf lands on absent {0:?}")]
    Absent(EffectTarget),
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
    /// A commutative movement declared on a cell that denominates
    /// nothing.
    ///
    /// `Delta` and `Reserve` move value and nothing else, so a cell they
    /// name is a cell that holds value — and what it holds is the
    /// declaration's to say, since a key is a hash and nothing inverts
    /// it. A movement through a cell that says nothing would hand out an
    /// edge no destination could disagree with.
    #[error("a movement declared on {0:?}, which denominates nothing")]
    UndenominatedMovement(SubstateKey),
    /// Two clauses reaching one cell and disagreeing about what it holds.
    ///
    /// The denomination chooses which handle a clause materializes, so a
    /// leaf one clause denominates and another does not would be handed
    /// out twice — as the cell value moves through and as the cell bytes
    /// are written to. A balance written through the second and debited
    /// through the first is value from nowhere, so the pair is refused
    /// before either handle exists.
    ///
    /// Refused at publish too, against the target expressions; this is
    /// the verdict two expressions that evaluate onto one cell reach.
    #[error("clauses disagree about what {0:?} holds")]
    MixedContents(EffectTarget),
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
    /// A handle whose clause was guarded out, reached anyway.
    ///
    /// The guest was handed the guard's verdict and branched the other
    /// way, so its control flow and its declaration disagree. Named
    /// rather than folded into an unknown handle because the diagnostic
    /// is the whole value: nothing was materialized here on purpose.
    #[error("a capability whose clause was not declared was reached")]
    UndeclaredBranch,
    /// Value credited to a cell denominated in some other resource.
    ///
    /// Reachable only from a package whose declaration says one thing and
    /// whose code does another, which is why it is judged here rather
    /// than taken on the declaration's word.
    #[error("a cell holding {cell:?} was credited with {carried:?}")]
    WrongResource {
        /// What the cell is denominated in.
        cell: Address,
        /// What the value going into it carries.
        carried: Address,
    },
    /// Value moved through a handle on a cell that denominates nothing.
    ///
    /// Unreachable through either runtime's canonical ABI — a movement
    /// handle is materialized only for a cell the declaration
    /// denominated — and kept as an honest error rather than a panic,
    /// like the handle refusals above it.
    #[error("handle {0} names a cell that denominates nothing, so no value moves through it")]
    BytesAsValue(u32),
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
    /// A split past what a bucket holds.
    #[error("a split of {amount} exceeds the {held} the bucket holds")]
    BucketUnderflow {
        /// What was asked for.
        amount: u128,
        /// What the bucket carries.
        held: u128,
    },
    /// A merge whose total is past the width an amount has.
    #[error("merging two buckets overflows an amount")]
    BucketOverflow,
    /// An operation reaching for the other kind of edge than the bucket
    /// carries: an amount where instances are held, or the reverse.
    #[error("this edge does not carry what the operation moves")]
    WrongEdgeKind,
    /// One instance reaching two places at once.
    #[error("instance {0} is already held")]
    InstanceHeldTwice(u128),
    /// An instance a body named and the collection does not hold, or
    /// named twice in one take.
    #[error("instance {0} is not held")]
    InstanceNotHeld(u128),
    /// An id list that is not a set: more ids than an edge may carry, or
    /// a repeated one.
    #[error("not an id set")]
    MalformedIdSet,
    /// A discarded bucket that still carried value.
    #[error("a bucket carrying {0} was let go of")]
    ValueDropped(u128),
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
    /// A proportional split by a share above one.
    #[error("a split by a share above one leaves no remainder")]
    ShareAboveOne,
    /// A wide arithmetic refusal.
    #[error(transparent)]
    Math(#[from] MathError),
    /// A store refusal.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A supply movement past what an accumulator can hold.
    #[error(transparent)]
    Supply(#[from] ModeError),
}

impl From<SessionTrap> for AbortReason {
    fn from(trap: SessionTrap) -> Self {
        match trap {
            SessionTrap::UnknownHandle(_) => Self::HandleUnknown,
            SessionTrap::WrongMode(_) => Self::HandleWrongMode,
            SessionTrap::UndeclaredBranch => Self::UndeclaredBranch,
            SessionTrap::IndexOutOfBounds { .. } => Self::EntryIndexOutOfBounds,
            SessionTrap::OrderOutsideInterval => Self::OrderOutsideInterval,
            SessionTrap::WriteCapExceeded { .. } => Self::IntervalWriteCapExceeded,
            SessionTrap::ReservationMissing => Self::ReservationMissing,
            SessionTrap::ReservationTaken => Self::ReservationAlreadyTaken,
            SessionTrap::IssuanceUngranted => Self::IssuanceUngranted,
            SessionTrap::BucketUnderflow { .. } => Self::BucketUnderflow,
            SessionTrap::BucketOverflow => Self::BucketOverflow,
            SessionTrap::WrongEdgeKind => Self::WrongEdgeKind,
            SessionTrap::InstanceHeldTwice(_) => Self::InstanceHeldTwice,
            SessionTrap::InstanceNotHeld(_) => Self::InstanceNotHeld,
            SessionTrap::MalformedIdSet => Self::MalformedEdgeCell,
            SessionTrap::ValueDropped(_) => Self::ValueDropped,
            SessionTrap::BadAmountCell(_) => Self::MalformedAmountCell,
            SessionTrap::CellUnderflow => Self::CellUnderflow,
            SessionTrap::CellOverflow => Self::CellOverflow,
            SessionTrap::NoInvocation => Self::EmissionOutsideInvocation,
            SessionTrap::EventTypeOutOfRange(_) => Self::EventTypeOutOfRange,
            SessionTrap::TooManyEvents => Self::EventCountExceeded,
            SessionTrap::EventPayloadTooLarge(_) => Self::EventPayloadTooLarge,
            SessionTrap::ShareAboveOne => Self::ShareAboveOne,
            SessionTrap::WrongResource { .. } => Self::WrongResource,
            SessionTrap::BytesAsValue(_) => Self::BytesAsValue,
            SessionTrap::Math(error) => error.into(),
            SessionTrap::Supply(error) => error.into(),
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

/// What one interval scan costs before any entry is counted, in the
/// boundary-byte terms the fuel schedule prices.
///
/// A placeholder like the footprint weights, and structural for the same
/// reason: the seek walks both overlay layers and the base whether or not
/// the interval holds anything, so a page's cost is not proportional to
/// what it returns and an empty one is not free.
pub const SCAN_SEEK_BYTES: usize = 64;

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
    /// What this transaction brought into and out of existence.
    ///
    /// Empty for almost every transaction: a transfer is a debit and a
    /// credit that sum to zero, so only one carrying resource authority
    /// moves supply at all. What a shard does with this is add it to its
    /// own accumulator, which is the whole of how the accumulator moves
    /// on this path.
    pub supply: SupplyDelta,
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
    /// What the scans above lifted out of the store, in boundary-byte
    /// terms, since whoever holds the fuel budget last drained it.
    ///
    /// A scan crosses no ABI boundary — a page stays host-side until an
    /// accessor asks it for one entry — so the copy metering that prices
    /// every other host call is blind to it. Left unpriced, the page a
    /// write invalidates would be free to re-materialize, and a body
    /// alternating a write with a count would buy an unbounded number of
    /// them at the cost of the loop alone.
    scanned: usize,
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
    /// What each capability's cell holds, by the same rep the capability
    /// table uses; `None` where the cell holds no value.
    ///
    /// The declaration's answer, carried here because the kernel's own is
    /// a hashed key it cannot invert. What it buys is that a movement can
    /// be judged against the resource its cell is denominated in without
    /// trusting anything the transaction said about which parameter went
    /// where — so a package whose metadata was authored rather than
    /// derived is held to the same rule as one the tracer wrote.
    cell_resources: Vec<Option<Address>>,
    /// The resource each live bucket carries, by the same rep the bucket
    /// table uses.
    ///
    /// Stamped where value comes into being — debited from a cell, taken
    /// against a grant, or handed in as a routed edge — and read where it
    /// lands, which is the pair that makes value crossing between two
    /// resources inexpressible rather than merely undeclared.
    ///
    /// Not an `Option`. Every producer names what it made: a cell a
    /// movement reached is one the declaration denominated, a grant is
    /// authority over one resource, and a split inherits from what it
    /// came off. A bucket that could carry nothing in particular would
    /// be one every destination had to admit.
    bucket_resources: Vec<Address>,
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
    /// Which resource a bucket is denominated in is the declaration's
    /// answer wherever it is asked —
    /// `outputs` for a produced edge, the cell's own key for a movement —
    /// and the kernel cannot invert a cell key to recover one, so a field
    /// for it would be right in one case and a guess in the rest.
    buckets: Vec<Option<Held>>,
    /// What this transaction brought into and out of existence, by
    /// resource.
    ///
    /// Accumulated as the operations happen rather than derived at the
    /// end, because the grant that authorised each one is gone by then:
    /// entering the next node takes it away, and the resource with it.
    supply: SupplyDelta,
    /// Whether the executing invocation may create value.
    ///
    /// One bit rather than a table of resources. What a grant fixes is
    /// *whether* a body may bring a bucket into existence with no cell
    /// debited behind it; which resource that value is denominated in is
    /// the method's declared outputs' answer, wherever the question is
    /// asked. The bit reaches the guest as a handle all the same, so it
    /// is visible in the export's own type and a body that was granted
    /// nothing has nothing to name.
    issuance: Option<Address>,
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
        denominations: &[Option<Address>],
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
        //
        // What each cell holds is folded as the table is built, because
        // the two clauses that disagree can be any two: a leaf one
        // denominates and another does not is a leaf handed out as a
        // vault and as a byte cell at once, and a balance written
        // through the byte handle is a balance nothing moved. Keyed by
        // what the target names rather than by the target, so two
        // intervals of one collection are one answer about its entries.
        let mut table = Vec::with_capacity(ordered.len());
        let mut holds: BTreeMap<Holds, bool> = BTreeMap::new();
        for (index, effect) in ordered.iter().enumerate() {
            let denominated = denominations.get(index).is_some_and(Option::is_some);
            if holds
                .insert(holds_of(effect.target), denominated)
                .is_some_and(|held| held != denominated)
            {
                return Err(MaterializeError::MixedContents(effect.target));
            }
            table.push(capability_for(&store, *effect, denominated)?);
        }
        // One transaction may not declare both an exclusive write and a
        // commutative mode on the same cell: the receipt records
        // absolutes for the one and movements for the other, and they
        // cannot compose.
        if let Some(key) = declared.self_conflicting() {
            return Err(MaterializeError::SelfConflicting(key));
        }

        // What a write requires of the leaf it lands on, judged where a
        // reservation's feasibility already is: over the committed
        // store, before the body runs, so a create that cannot create
        // aborts rather than trapping inside a guest.
        //
        // Exhaustive over the target shapes, never skipping one it does
        // not read: a requirement this cannot honour is refused, because
        // a declaration that states a precondition nothing enforces is
        // worse than one that never published.
        for effect in declared.iter() {
            let Mode::Write { requires } = effect.mode else {
                continue;
            };
            if requires == Presence::Either {
                continue;
            }
            let held = match effect.target {
                // The two shapes that name one leaf. An entry's presence
                // is the same question a custody gate's possession read
                // asks, over the same width-one interval.
                EffectTarget::Point(key) => store.read(key)?.is_some(),
                EffectTarget::Entry {
                    owner,
                    collection,
                    order,
                } => !store
                    .entries_in_range(owner, collection, order, order, 1)?
                    .is_empty(),
                // An interval names no leaf for a requirement to be
                // about — it stays valid whatever enters or leaves it,
                // which is the property that makes it declarable at all.
                // Refused at publish, and again here, because metadata
                // can be authored rather than derived.
                EffectTarget::Range { .. } => {
                    return Err(MaterializeError::Unsupported(Box::new(effect)));
                }
            };
            match (requires, held) {
                (Presence::Absent, true) => return Err(MaterializeError::Occupied(effect.target)),
                (Presence::Present, false) => return Err(MaterializeError::Absent(effect.target)),
                _ => {}
            }
        }

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
            scanned: 0,
            written: BTreeMap::new(),
            invocation: None,
            events: Vec::new(),
            supply: SupplyDelta::default(),
            cell_resources: denominations.to_vec(),
            bucket_resources: Vec::new(),
            buckets: Vec::new(),
            issuance: None,
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
    pub fn open_bucket(&mut self, held: Held, resource: Address) -> u32 {
        let rep = u32::try_from(self.buckets.len()).expect("bounded");
        self.buckets.push(Some(held));
        self.bucket_resources.push(resource);
        rep
    }

    /// What the cell behind a capability holds, where it holds value.
    fn cell_resource(&self, rep: u32) -> Option<Address> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.cell_resources.get(index))
            .copied()
            .flatten()
    }

    /// What the cell behind a capability holds, for a movement through
    /// it.
    ///
    /// The check and the answer are one lookup: a movement needs the
    /// resource, and a cell that does not name one is a cell no value
    /// moves through.
    fn value_of(&self, rep: u32) -> Result<Address, SessionTrap> {
        self.cell_resource(rep)
            .ok_or(SessionTrap::BytesAsValue(rep))
    }

    /// What the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep past the bucket table.
    fn bucket_resource(&self, rep: u32) -> Result<Address, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.bucket_resources.get(index))
            .copied()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// Judge a credit: the value going into a cell is the resource that
    /// cell holds, or it does not go in.
    ///
    /// One comparison with nothing to skip. Both sides are known by
    /// construction — a cell a movement reaches was denominated by the
    /// declaration, and a bucket carries what it was made from — so the
    /// question is only whether they agree.
    fn judge_credit(&self, rep: u32, funds: u32) -> Result<(), SessionTrap> {
        let cell = self.value_of(rep)?;
        let carried = self.bucket_resource(funds)?;
        if cell == carried {
            Ok(())
        } else {
            Err(SessionTrap::WrongResource { cell, carried })
        }
    }

    /// What the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub fn bucket(&self, rep: u32) -> Result<Held, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.buckets.get(index))
            .cloned()
            .flatten()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// The amount the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::WrongEdgeKind`] for a bucket carrying instances:
    /// what a movement moves is an amount, and a named thing is not one.
    pub fn bucket_amount(&self, rep: u32) -> Result<u128, SessionTrap> {
        match self.bucket(rep)? {
            Held::Amount(amount) => Ok(amount),
            Held::Instances(_) => Err(SessionTrap::WrongEdgeKind),
        }
    }

    /// Takes the bucket at `rep` back out of the table: the kernel holds
    /// the value again and the rep names nothing afterwards.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub fn take_bucket(&mut self, rep: u32) -> Result<Held, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.buckets.get_mut(index))
            .and_then(Option::take)
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// Take the named entries of a write interval, as the instances they
    /// were.
    ///
    /// The removal and the edge are one operation, which is what a
    /// movement is for an amount cell and what this is for a collection:
    /// a body cannot hand on instances it left where they were. Naming
    /// none yields an empty bucket, so a method that moves nothing needs
    /// no way to name one.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`]: a malformed id cell, an id outside the
    /// declared interval, one the collection does not hold, or more
    /// entries than the interval's cap admits.
    pub fn range_take(&mut self, rep: u32, ids: &[u64]) -> Result<u32, SessionTrap> {
        let interval = self.instance_interval(rep)?;
        let resource = self.value_of(rep)?;
        // The decoder refuses a repeated id, so the set below loses
        // nothing to dedup and a count is an instance count.
        let ids = distinct_ids(ids).ok_or(SessionTrap::MalformedIdSet)?;
        // Every entry is charged and removed, or none is: the budget is
        // what the declaration bought, and a take that overran it must
        // leave the collection alone.
        let mut taken = BTreeSet::new();
        for id in ids {
            let order = u128::from(id);
            if !interval.holds(order) {
                return Err(SessionTrap::OrderOutsideInterval);
            }
            // Asked at the instance's own key rather than of the
            // interval's page. The cap bounds how many entries execution
            // may touch, and a take names at most an edge's worth — so
            // answering from a page would make reachability a function of
            // how many lower-ordered instances sit in front of this one,
            // and a holder past the cap could never move its later ids.
            let held = self.probe(interval.owner, interval.collection, order)?;
            if !held {
                return Err(SessionTrap::InstanceNotHeld(order));
            }
            self.charge_write(rep, order, interval.cap)?;
            taken.insert(order);
        }
        for order in &taken {
            self.store
                .entry_remove(interval.owner, interval.collection, *order)?;
        }
        self.invalidate(interval.owner, interval.collection);
        Ok(self.open_bucket(Held::Instances(taken), resource))
    }

    /// File every instance the bucket at `funds` carries as an entry of a
    /// write interval, at the order it was taken under.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`]: an instance outside the declared interval, a
    /// bucket carrying an amount, or a cap the filing would overrun.
    pub fn range_put(&mut self, rep: u32, funds: u32, value: &[u8]) -> Result<(), SessionTrap> {
        let interval = self.instance_interval(rep)?;
        self.judge_credit(rep, funds)?;
        let Held::Instances(ids) = self.bucket(funds)? else {
            return Err(SessionTrap::WrongEdgeKind);
        };
        for order in &ids {
            if !interval.holds(*order) {
                return Err(SessionTrap::OrderOutsideInterval);
            }
        }
        for order in &ids {
            self.charge_write(rep, *order, interval.cap)?;
        }
        for order in &ids {
            self.store
                .entry_write(interval.owner, interval.collection, *order, value.to_vec())?;
        }
        self.invalidate(interval.owner, interval.collection);
        self.take_bucket(funds).map(|_| ())
    }

    /// Split `amount` off the bucket at `rep`, as a new bucket.
    ///
    /// The kernel performs the subtraction, so the half that comes off
    /// and the half left behind are one operation and a body writes down
    /// neither.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a split past what the bucket holds.
    pub fn bucket_take(&mut self, rep: u32, amount: u128) -> Result<u32, SessionTrap> {
        // A quantity divides what a quantity is. Splitting an instance
        // set by a number has no answer — which instances? — so the
        // vocabulary refuses rather than picking.
        let held = self.bucket_amount(rep)?;
        let resource = self.bucket_resource(rep)?;
        let left = held
            .checked_sub(amount)
            .ok_or(SessionTrap::BucketUnderflow { amount, held })?;
        self.set_bucket(rep, Held::Amount(left));
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// Split `num/den` of the bucket at `rep` off, as a bucket.
    ///
    /// The share is computed and the remainder is *derived*: what stays
    /// behind is the subtraction, never a second multiplication. That is
    /// what makes conservation arithmetic rather than checked — the two
    /// outputs sum to the input because one of them is defined as the
    /// difference, so there is no rounding argument to get wrong and no
    /// way to write the bug where distributed parts do not sum to the
    /// whole. The supply accumulators downstream assume exactly that.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::WrongEdgeKind`] for an instance edge, which a
    /// proportion cannot divide; [`SessionTrap::Math`] on a zero
    /// denominator; [`SessionTrap::ShareAboveOne`] past one.
    pub fn bucket_split(&mut self, rep: u32, num: U256, den: U256) -> Result<u32, SessionTrap> {
        let held = self.bucket_amount(rep)?;
        if den.is_zero() {
            return Err(SessionTrap::Math(MathError::DivideByZero));
        }
        if num > den {
            return Err(SessionTrap::ShareAboveOne);
        }
        // The share is at most what is held, because the ratio is at most
        // one — so the narrowing and the subtraction below are both
        // total, and neither needs a check the type system would then
        // have to explain.
        let share = mul_div(U256::from_u128(held), num, den, Rounding::Down)?
            .to_u128()
            .ok_or(SessionTrap::Math(MathError::Overflow))?;
        let resource = self.bucket_resource(rep)?;
        let left = held
            .checked_sub(share)
            .ok_or(SessionTrap::BucketUnderflow {
                amount: share,
                held,
            })?;
        self.set_bucket(rep, Held::Amount(left));
        Ok(self.open_bucket(Held::Amount(share), resource))
    }

    /// Merge the bucket at `other` into the one at `rep`, consuming it.
    ///
    /// The consumed bucket leaves the table before the merge, which is
    /// what an owned argument means and what makes a merge of a bucket
    /// into itself say so: the one bucket is gone by the time the other
    /// is looked up, so the second lookup is the unknown handle the
    /// guest's own table already agrees it is. Reading both first would
    /// instead add a quantity to itself and put the total back in the
    /// slot the take had just emptied, which is value from nowhere.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a total past an amount's width.
    pub fn bucket_put(&mut self, rep: u32, other: u32) -> Result<(), SessionTrap> {
        // A merge makes two edges one, so it is the same question a cell
        // credit asks — with the receiving edge's resource in place of a
        // cell's. Both lookups answer for a rep the table has ever held,
        // so a merge into itself still reaches the take below and fails
        // there, which is where the guest's own table agrees it should.
        let into = self.bucket_resource(rep)?;
        let carried = self.bucket_resource(other)?;
        if into != carried {
            return Err(SessionTrap::WrongResource {
                cell: into,
                carried,
            });
        }
        let added = self.take_bucket(other)?;
        let merged = match (self.bucket(rep)?, added) {
            (Held::Amount(held), Held::Amount(added)) => {
                Held::Amount(held.checked_add(added).ok_or(SessionTrap::BucketOverflow)?)
            }
            // Instances are named, so a merge is a union and a name
            // appearing twice is one instance in two places.
            (Held::Instances(mut held), Held::Instances(added)) => {
                for id in added {
                    if !held.insert(id) {
                        return Err(SessionTrap::InstanceHeldTwice(id));
                    }
                }
                Held::Instances(held)
            }
            _ => return Err(SessionTrap::WrongEdgeKind),
        };
        self.set_bucket(rep, merged);
        Ok(())
    }

    /// Replace what a live bucket carries. The rep is one `bucket` has
    /// already resolved, so there is no slot to miss.
    fn set_bucket(&mut self, rep: u32, held: Held) {
        if let Some(slot) = usize::try_from(rep)
            .ok()
            .and_then(|index| self.buckets.get_mut(index))
        {
            *slot = Some(held);
        }
    }

    /// A bucket handle the guest let go of.
    ///
    /// The canonical ABI delivers the drop and the kernel decides what it
    /// means. What it decides is that value is not forgotten: a bucket is
    /// put into a cell or handed back, and one carrying anything at all
    /// that reaches here is the loss the linear model exists to exclude.
    /// That delivery is the whole of what an owned handle buys over a
    /// value a body could simply let fall out of scope, and it is why a
    /// record could not have carried this.
    ///
    /// An empty bucket drops freely, because there is nothing to lose.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket,
    /// and [`SessionTrap::ValueDropped`] for one that still carries value.
    pub fn drop_bucket(&mut self, rep: u32) -> Result<(), SessionTrap> {
        let held = self.bucket(rep)?;
        if !held.is_empty() {
            return Err(SessionTrap::ValueDropped(held.quantity()));
        }
        self.take_bucket(rep).map(|_| ())
    }

    fn capability(&self, rep: u32) -> Result<Capability, SessionTrap> {
        if rep == ABSENT_REP {
            return Err(SessionTrap::UndeclaredBranch);
        }
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

    /// Whether the holder keeps the instance at `order`, for the
    /// kernel's custody gate — the same view an entry capability serves,
    /// over the collection the gate admission lowered names, which is
    /// declared by construction like the gate's cells.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`] the store raises.
    pub fn declared_holds_instance(
        &mut self,
        owner: Address,
        collection: CollectionId,
        order: u128,
    ) -> Result<bool, SessionTrap> {
        Ok(!self
            .store
            .entries_in_range(owner, collection, order, order, 1)?
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

    /// What an amount cell holds.
    ///
    /// The one question about a balance that moves none of it, and the
    /// reason a value cell needs a read at all: a curve is a function of
    /// its reserves. An absent cell is nothing, and a stored cell that is
    /// not an amount is the state's own defect.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn amount_cell_balance(&mut self, rep: u32) -> Result<u128, SessionTrap> {
        let Capability::Amount(key) = self.capability(rep)? else {
            return Err(SessionTrap::WrongMode(rep));
        };
        self.amount_cell(key)
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
        let resource = self.value_of(rep)?;
        Ok(self.open_bucket(Held::Amount(amount), resource))
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
        self.judge_credit(rep, funds)?;
        let amount = self.bucket_amount(funds)?;
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
        let Capability::Amount(key) = self.capability(rep)? else {
            return Err(SessionTrap::WrongMode(rep));
        };
        self.judge_credit(rep, funds)?;
        let held = self.amount_cell(key)?;
        let amount = self.bucket_amount(funds)?;
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
        let Capability::Amount(key) = self.capability(rep)? else {
            return Err(SessionTrap::WrongMode(rep));
        };
        let resource = self.value_of(rep)?;
        let held = self.amount_cell(key)?;
        let left = held.checked_sub(amount).ok_or(SessionTrap::CellUnderflow)?;
        self.store.write(key, encode_amount(left).to_vec())?;
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// Create `amount` of what this invocation issues, as a bucket.
    ///
    /// The one bucket with no cell behind it. `rep` names the grant, of
    /// which an invocation has at most one — the handle's whole content
    /// is that it exists.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a mint against a grant this
    /// invocation was never given.
    pub fn mint(&mut self, rep: u32, amount: u128) -> Result<u32, SessionTrap> {
        if rep != ISSUER_REP {
            return Err(SessionTrap::UnknownHandle(rep));
        }
        let Some(resource) = self.issuance else {
            return Err(SessionTrap::IssuanceUngranted);
        };
        self.supply.mint(resource, amount)?;
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// Create the named instances of what this invocation issues.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a mint against a grant this
    /// invocation was never given.
    pub fn mint_instances(&mut self, rep: u32, ids: &[u64]) -> Result<u32, SessionTrap> {
        if rep != ISSUER_REP {
            return Err(SessionTrap::UnknownHandle(rep));
        }
        let Some(resource) = self.issuance else {
            return Err(SessionTrap::IssuanceUngranted);
        };
        let named = distinct_ids(ids).ok_or(SessionTrap::MalformedIdSet)?;
        let mut instances = BTreeSet::new();
        for id in named {
            if !instances.insert(u128::from(id)) {
                return Err(SessionTrap::InstanceHeldTwice(u128::from(id)));
            }
        }
        // An instance's supply is its existence: what a non-fungible
        // mints is a count, which is what its holdings are measured in.
        self.supply.mint(
            resource,
            u128::try_from(instances.len()).unwrap_or(u128::MAX),
        )?;
        Ok(self.open_bucket(Held::Instances(instances), resource))
    }

    /// Destroy what this invocation issues, consuming the bucket.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a burn by an invocation granted
    /// nothing.
    pub fn burn(&mut self, rep: u32, funds: u32) -> Result<(), SessionTrap> {
        if rep != ISSUER_REP {
            return Err(SessionTrap::UnknownHandle(rep));
        }
        let Some(resource) = self.issuance else {
            return Err(SessionTrap::IssuanceUngranted);
        };
        // A grant names one resource, so what it destroys is that one:
        // burning through another instance's grant would be destroying
        // value this invocation has no authority over.
        let carried = self.bucket_resource(funds)?;
        if carried != resource {
            return Err(SessionTrap::WrongResource {
                cell: resource,
                carried,
            });
        }
        let destroyed = self.bucket(funds)?.quantity();
        self.supply.burn(resource, destroyed)?;
        self.take_bucket(funds).map(|_| ())
    }

    /// Grant the executing invocation authority over one resource: to
    /// mint it and to burn it, which are two directions of one right.
    ///
    /// Read off the method's own declaration by whoever entered the node;
    /// entering the next one takes it away again. The resource is the
    /// grant's whole content — what a body may bring into or out of
    /// existence is fixed before it runs, and there is no second one it
    /// could name.
    pub const fn grant_issuance(&mut self, resource: Address) {
        self.issuance = Some(resource);
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
        let resource = self.value_of(rep)?;
        if !self.taken.insert(rep) {
            return Err(SessionTrap::ReservationTaken);
        }
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// The interval a range handle names, whichever mode it carries.
    ///
    /// For the questions both modes answer — how many entries, what is at
    /// an index, which collection a scan belongs to.
    fn interval(&self, rep: u32) -> Result<Interval, SessionTrap> {
        match self.capability(rep)? {
            Capability::RangeRead(interval)
            | Capability::RangeWrite(interval)
            | Capability::InstanceRange(interval) => Ok(interval),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The interval a byte-writing handle names.
    ///
    /// Every entry rewrite asks through here, so the refusal a read
    /// interval meets is stated once rather than repeated at each of
    /// them — and a mutation added later cannot forget to ask, because
    /// there is no other way to reach the interval it would change.
    fn write_interval(&self, rep: u32) -> Result<Interval, SessionTrap> {
        match self.capability(rep)? {
            Capability::RangeWrite(interval) => Ok(interval),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The interval an instance-moving handle names — the same
    /// statement as [`Self::write_interval`], for the entries that are
    /// value rather than bytes.
    fn instance_interval(&self, rep: u32) -> Result<Interval, SessionTrap> {
        match self.capability(rep)? {
            Capability::InstanceRange(interval) => Ok(interval),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// Read a run of entries, charging what it lifted to
    /// [`Self::take_scan_debt`].
    ///
    /// The seek is charged whatever the run holds, because walking the
    /// layers and the base is what an empty one costs too.
    fn lift(
        &mut self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        cap: u32,
    ) -> Result<Vec<(u128, Vec<u8>)>, SessionTrap> {
        let entries = self
            .store
            .entries_in_range(owner, collection, lo, hi, cap)?;
        let lifted = entries.iter().fold(SCAN_SEEK_BYTES, |total, (_, value)| {
            total
                .saturating_add(AMOUNT_CELL_BYTES)
                .saturating_add(value.len())
        });
        self.scanned = self.scanned.saturating_add(lifted);
        Ok(entries)
    }

    /// Whether one entry is there, on the same terms a page is read.
    fn probe(
        &mut self,
        owner: Address,
        collection: CollectionId,
        order: u128,
    ) -> Result<bool, SessionTrap> {
        Ok(!self.lift(owner, collection, order, order, 1)?.is_empty())
    }

    /// Materialize the interval behind `rep` if it is not already.
    fn scan(&mut self, rep: u32) -> Result<(), SessionTrap> {
        if self.scans.contains_key(&rep) {
            return Ok(());
        }
        let interval = self.interval(rep)?;
        let entries = self.lift(
            interval.owner,
            interval.collection,
            interval.lo,
            interval.hi,
            interval.cap,
        )?;
        self.scans.insert(rep, entries);
        Ok(())
    }

    /// What interval scans have lifted out of the store since this was
    /// last asked, in the boundary-byte terms the fuel schedule prices.
    ///
    /// Called by whoever holds the fuel budget, after every host call
    /// that can reach a scan. [`Self::finish`] refuses a session that
    /// still owes, so an accessor added later cannot quietly scan for
    /// free — it fails every test that runs it.
    pub const fn take_scan_debt(&mut self) -> usize {
        std::mem::replace(&mut self.scanned, 0)
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
                self.interval(*rep)
                    .is_ok_and(|scanned| scanned.owner == owner && scanned.collection == collection)
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
        let interval = self.write_interval(rep)?;
        self.scan(rep)?;
        let order = *indexed(&self.scans[&rep], index).map(|(order, _)| order)?;
        self.charge_write(rep, order, interval.cap)?;
        self.store
            .entry_write(interval.owner, interval.collection, order, value)?;
        self.invalidate(interval.owner, interval.collection);
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
        let interval = self.write_interval(rep)?;
        if !interval.holds(order) {
            return Err(SessionTrap::OrderOutsideInterval);
        }
        self.charge_write(rep, order, interval.cap)?;
        self.store
            .entry_write(interval.owner, interval.collection, order, value)?;
        self.invalidate(interval.owner, interval.collection);
        Ok(())
    }

    /// Remove the entry at `index` through a write interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), SessionTrap> {
        let interval = self.write_interval(rep)?;
        self.scan(rep)?;
        let order = *indexed(&self.scans[&rep], index).map(|(order, _)| order)?;
        self.charge_write(rep, order, interval.cap)?;
        self.store
            .entry_remove(interval.owner, interval.collection, order)?;
        self.invalidate(interval.owner, interval.collection);
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
        self.issuance = None;
    }

    /// Leave the current invocation. An emission outside one is a runner
    /// defect and traps rather than guessing an emitter.
    pub const fn leave_invocation(&mut self) {
        self.invocation = None;
        self.issuance = None;
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
        for index in 0..self.table.len() {
            if let Capability::Reserve { key, .. } = self.table[index] {
                if settles.contains_key(&key) {
                    continue;
                }
                // A remote reservation settles at its owning shard; here
                // the hold releases and the receipt keeps the amount as
                // the outbound record.
                let settled = if self.locality.is_local(key.owner) {
                    self.store.settle(key, self.tx)
                } else {
                    self.store.release(key, self.tx)
                };
                match settled {
                    Ok(amount) => {
                        settles.insert(key, amount);
                    }
                    // An exclusive write earlier in this group drained the
                    // cell below the reservation it still covers. The
                    // reserver lost that race, and the refusal left its
                    // hold standing, so the amount is still readable.
                    Err(StoreError::HeldExceedsCommitted(_)) => {
                        let amount = self
                            .store
                            .held_reservation(key, self.tx)
                            .unwrap_or_default();
                        return Ok(Err(Outcome::Infeasible { key, amount }));
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
    ///
    /// # Panics
    ///
    /// On an undrained scan debt, which is a host adapter that reached a
    /// scan without charging for it.
    pub fn finish(
        mut self,
        outcome: Outcome,
        fuel: u64,
    ) -> Result<(Receipt, OverlayStore), FinishError> {
        assert_eq!(
            self.scanned, 0,
            "a host call reached a scan without charging what it lifted"
        );
        // Value first, because a transaction that lost some has nothing
        // else worth judging. A bucket still carrying anything here was
        // debited from a cell and never put into one, and the drop the
        // canonical ABI delivers is only reached by a body that lets a
        // handle go — a body that simply keeps one reaches nothing at
        // all. So the table is the account, and it has to balance for the
        // transaction to commit.
        if self.buckets.iter().flatten().any(|held| !held.is_empty()) {
            return Ok(abort_with(
                self.store,
                Outcome::UserError {
                    reason: AbortReason::ValueDropped,
                },
                fuel,
            ));
        }
        // Movements next: the pending deltas, as checked totals.
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
        // Value exists because a transaction that committed created it.
        // Every other outcome leaves the shard as it found it, so what an
        // uncommitted one said it minted or burned is a claim about a
        // world that never happened — the same rule its events are under,
        // applied here rather than left to whoever picked the outcome.
        let supply = if matches!(outcome, Outcome::Completed { .. }) {
            self.supply
        } else {
            SupplyDelta::default()
        };
        Ok((
            Receipt {
                outcome,
                delta,
                events: self.events,
                supply,
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
            // is one of them — including value it said it brought into or
            // out of existence, which never happened either.
            events: Vec::new(),
            supply: SupplyDelta::default(),
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

/// What a target names as the thing whose contents are one fact: the
/// leaf a point names, or the collection an entry or an interval sits in.
///
/// Not the target itself, because two intervals of one collection are two
/// targets over one set of entries — so an interval saying its entries
/// are instances and an overlapping one saying they are bytes are two
/// answers about the same entries.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Holds {
    /// One leaf.
    Leaf(SubstateKey),
    /// Every entry of one collection.
    Entries(Address, CollectionId),
}

/// Which cell's contents an effect is an answer about.
const fn holds_of(target: EffectTarget) -> Holds {
    match target {
        EffectTarget::Point(key) => Holds::Leaf(key),
        EffectTarget::Entry {
            owner, collection, ..
        }
        | EffectTarget::Range {
            owner, collection, ..
        } => Holds::Entries(owner, collection),
    }
}

/// The interval a collection target names; `None` for a point key.
///
/// An entry is the width-one interval at its order — the same
/// normalization the oracle's coverage walk applies — so a declared entry
/// and a declared range reach the store through one shape.
const fn interval_of(target: EffectTarget) -> Option<Interval> {
    match target {
        EffectTarget::Point(_) => None,
        EffectTarget::Entry {
            owner,
            collection,
            order,
        } => Some(Interval {
            owner,
            collection,
            lo: order,
            hi: order,
            cap: 1,
        }),
        EffectTarget::Range {
            owner,
            collection,
            lo,
            hi,
            cap,
        } => Some(Interval {
            owner,
            collection,
            lo,
            hi,
            cap,
        }),
    }
}

/// The capability form of one declared effect: the world-design mapping.
/// Entry targets are degenerate one-entry intervals, so collection access
/// needs exactly two resource shapes.
fn capability_for(
    store: &OverlayStore,
    effect: Effect,
    denominated: bool,
) -> Result<Capability, MaterializeError> {
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
        // What a cell holds chooses the handle. The two share no
        // operation, so a body reaching for the wrong one is holding a
        // type that does not have it rather than meeting a refusal.
        (EffectTarget::Point(key), Mode::Write { .. }) => {
            let key = locked_checked(key)?;
            Ok(if denominated {
                Capability::Amount(key)
            } else {
                Capability::Write(key)
            })
        }
        // The two modes that move value and do nothing else. A cell
        // they name holds value, so the declaration has to say what —
        // judged here rather than at the movement, because a declaration
        // that cannot be materialized is one no body should run against.
        (EffectTarget::Point(key), Mode::Delta) => {
            if denominated {
                Ok(Capability::Delta(locked_checked(key)?))
            } else {
                Err(MaterializeError::UndenominatedMovement(key))
            }
        }
        (EffectTarget::Point(key), Mode::Reserve { amount }) => {
            if denominated {
                Ok(Capability::Reserve {
                    key: locked_checked(key)?,
                    amount,
                })
            } else {
                Err(MaterializeError::UndenominatedMovement(key))
            }
        }
        // Point targets are spoken for above, so what is left is a
        // collection one — and the two spell the same interval, the mode
        // choosing only which capability carries it.
        (target, mode @ (Mode::Read | Mode::Write { .. })) => interval_of(target)
            .map(|interval| match (mode, denominated) {
                (Mode::Write { .. }, true) => Capability::InstanceRange(interval),
                (Mode::Write { .. }, false) => Capability::RangeWrite(interval),
                _ => Capability::RangeRead(interval),
            })
            .ok_or_else(|| MaterializeError::Unsupported(Box::new(effect))),
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
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_vm_effects::{
        ABSENT_REP, AbortReason, Address, AddressClass, CollectionId, Effect, EffectConflict,
        EffectSet, EffectTarget, Hash32, Mode, SlotId, SubstateKey, TestHasher, child_key,
    };
    use hyperscale_vm_types::Presence;

    use super::{
        Capability, EnvInputs, Event, Held, Holds, KernelSession, MAX_EVENT_PAYLOAD_BYTES,
        MAX_EVENT_TYPES, MAX_EVENTS_PER_TX, MaterializeError, MathError, Outcome, SCAN_SEEK_BYTES,
        SessionTrap, U256, holds_of,
    };
    use crate::ledger::AmountLedger;
    use crate::modes::{AMOUNT_CELL_BYTES, TxHash, decode_amount, encode_amount};
    use crate::overlay::OverlayStore;
    use crate::store::{MemoryStore, StoreError, WorkingStore};

    fn key(byte: u8) -> SubstateKey {
        child_key(
            &TestHasher,
            Address::new([byte; 31], AddressClass::Component),
            SlotId(1),
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

    /// Materialize one write over a store, for the presence tests.
    fn presence_verdict(
        store: MemoryStore,
        target: EffectTarget,
        requires: Presence,
    ) -> Result<(), MaterializeError> {
        let set = declared(&[Effect {
            target,
            mode: Mode::Write { requires },
        }]);
        let ordered = ord(&set);
        KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &set,
            &ordered,
            &holding(&ordered),
            tx(1),
            env(),
            hash,
        )
        .map(|_| ())
    }

    /// A write says what it requires of the leaf, and the shard holding
    /// the leaf judges it before the body runs — the same seam, and the
    /// same class of verdict, as an infeasible reservation.
    ///
    /// Both shapes that name one leaf answer, because the requirement is
    /// about the leaf rather than about how the target spells it: a cell
    /// and a collection entry are each exactly one.
    #[test]
    fn a_write_requiring_a_presence_the_leaf_does_not_have_refuses() {
        let cell = EffectTarget::Point(key(0xC1));
        let owner = Address::new([0xC1; 31], AddressClass::Component);
        let collection = CollectionId([9; 16]);
        let entry = EffectTarget::Entry {
            owner,
            collection,
            order: 7,
        };
        let empty = |_: EffectTarget| MemoryStore::new();
        let occupied = |target: EffectTarget| {
            let mut store = MemoryStore::new();
            match target {
                EffectTarget::Point(key) => {
                    store.write(key, vec![7]).expect("seed");
                }
                EffectTarget::Entry {
                    owner,
                    collection,
                    order,
                } => {
                    store
                        .entry_write(owner, collection, order, vec![7])
                        .expect("seed");
                }
                EffectTarget::Range { .. } => unreachable!("not a leaf"),
            }
            store
        };

        for target in [cell, entry] {
            // A create lands only where nothing is.
            assert_eq!(
                presence_verdict(empty(target), target, Presence::Absent),
                Ok(()),
                "{target:?}"
            );
            assert_eq!(
                presence_verdict(occupied(target), target, Presence::Absent),
                Err(MaterializeError::Occupied(target)),
                "{target:?}"
            );

            // And its dual.
            assert_eq!(
                presence_verdict(occupied(target), target, Presence::Present),
                Ok(()),
                "{target:?}"
            );
            assert_eq!(
                presence_verdict(empty(target), target, Presence::Present),
                Err(MaterializeError::Absent(target)),
                "{target:?}"
            );

            // An ordinary write is indifferent, which is what every
            // declaration that says nothing means.
            for store in [empty(target), occupied(target)] {
                assert_eq!(
                    presence_verdict(store, target, Presence::Either),
                    Ok(()),
                    "{target:?}"
                );
            }
        }
    }

    /// An interval names no leaf, so a requirement about one is refused
    /// rather than read past — the publish gate says the same, and this
    /// is what holds for metadata that was authored rather than derived.
    #[test]
    fn a_presence_requirement_on_an_interval_refuses() {
        let range = EffectTarget::Range {
            owner: Address::new([0xC3; 31], AddressClass::Component),
            collection: CollectionId([9; 16]),
            lo: 0,
            hi: u128::MAX,
            cap: 4,
        };
        for requires in [Presence::Absent, Presence::Present] {
            assert_eq!(
                presence_verdict(MemoryStore::new(), range, requires),
                Err(MaterializeError::Unsupported(Box::new(Effect {
                    target: range,
                    mode: Mode::Write { requires },
                }))),
                "{requires:?}"
            );
        }
        // The indifferent one is every range write there has ever been.
        assert_eq!(
            presence_verdict(MemoryStore::new(), range, Presence::Either),
            Ok(())
        );
    }

    /// Two clauses on one cell are one access, and what it requires is
    /// what both require — unless they require opposite things, which is
    /// a declaration nothing could satisfy.
    #[test]
    fn presence_requirements_on_one_cell_meet_or_refuse() {
        let key = key(0xC2);
        let write = |requires| Effect {
            target: EffectTarget::Point(key),
            mode: Mode::Write { requires },
        };
        let fold = |a, b| {
            let mut set = EffectSet::new();
            set.insert(write(a))?;
            set.insert(write(b))?;
            Ok::<_, EffectConflict>(set.iter().collect::<Vec<_>>())
        };

        // A named requirement wins over the indifferent one, in either
        // order, and the set holds one access rather than two.
        for named in [Presence::Absent, Presence::Present] {
            for pair in [(Presence::Either, named), (named, Presence::Either)] {
                assert_eq!(fold(pair.0, pair.1), Ok(vec![write(named)]));
            }
            assert_eq!(fold(named, named), Ok(vec![write(named)]));
        }

        // Opposite requirements are refused where the second is written.
        assert_eq!(
            fold(Presence::Absent, Presence::Present),
            Err(EffectConflict::Presence)
        );
        assert_eq!(
            fold(Presence::Present, Presence::Absent),
            Err(EffectConflict::Presence)
        );
    }

    #[test]
    fn the_table_follows_the_clause_order_not_the_set_order() {
        // A handle's rep is its index here and a guest's parameters are
        // positional, so the table must be the order the author wrote —
        // never the set's, which is a comparison over hash-derived keys.
        let (first, second) = (key(0xA1), key(0xA2));
        let write = |k| Effect {
            target: EffectTarget::Point(k),
            mode: Mode::Write {
                requires: Presence::Either,
            },
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
            &holding(&reversed),
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
            mode: Mode::Write {
                requires: Presence::Either,
            },
        };
        let set = declared(&[write, write]);
        assert_eq!(set.len(), 1, "the set folds them");

        let session = KernelSession::materialize(
            OverlayStore::new(Arc::new(MemoryStore::new())),
            &set,
            &[write, write],
            &holding(&[write, write]),
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
            &holding(&[reserve, reserve]),
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
            &holding(&[reserve(5), reserve(6)]),
            tx(1),
            env(),
            hash,
        )
        .expect("11 reserved against 100 is feasible");

        assert_eq!(session.reserve_amount(0), Ok(5));
        assert_eq!(session.reserve_amount(1), Ok(6));
    }

    /// What every cell these fixtures move value through holds.
    const RESOURCE: Address = Address::new([0xE1; 31], AddressClass::Resource);

    /// What each entry of an ordered declaration holds.
    ///
    /// A movement names a cell that holds value, and a hand-built set has
    /// no clause left to say what — so a fixture standing in for a
    /// signature says it here, or the movement is refused before any body
    /// runs.
    ///
    /// Answered per cell rather than per clause, because that is the
    /// shape of the fact: every clause reaching a cell some movement
    /// reaches says the same thing about it, which is what
    /// [`MaterializeError::MixedContents`] holds a signature to.
    fn holding(ordered: &[Effect]) -> Vec<Option<Address>> {
        let value: BTreeSet<Holds> = ordered
            .iter()
            .filter(|effect| matches!(effect.mode, Mode::Delta | Mode::Reserve { .. }))
            .map(|effect| holds_of(effect.target))
            .collect();
        ordered
            .iter()
            .map(|effect| value.contains(&holds_of(effect.target)).then_some(RESOURCE))
            .collect()
    }

    /// A session over cells that all hold value — what a fixture wants
    /// when the write it declares is a debit rather than a byte write.
    fn session_holding(store: MemoryStore, set: &EffectSet) -> KernelSession {
        let ordered = ord(set);
        let holds: Vec<_> = ordered.iter().map(|_| Some(RESOURCE)).collect();
        KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            set,
            &ordered,
            &holds,
            tx(1),
            env(),
            hash,
        )
        .expect("materializes")
    }

    fn session_over(store: MemoryStore, set: &EffectSet) -> KernelSession {
        KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            set,
            &ord(set),
            &holding(&ord(set)),
            tx(1),
            env(),
            hash,
        )
        .expect("materializes")
    }

    /// A deterministic generator: the property is exact, so the corpus
    /// only has to be wide and reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// A `u128` with a uniformly chosen bit width, so small values
        /// are as common as wide ones.
        fn amount(&mut self) -> u128 {
            let bits = self.next() % 129;
            if bits == 0 {
                return 0;
            }
            let value = u128::from(self.next()) | (u128::from(self.next()) << 64);
            value >> (128 - bits)
        }
    }

    /// The property the primitive exists for: the two outputs sum to the
    /// input, for every quantity and every share at or under one, with no
    /// rounding argument anywhere in the statement.
    #[test]
    fn a_split_conserves_what_it_divides() {
        let set = declared(&[]);
        let mut session = session_over(MemoryStore::new(), &set);
        let mut rng = Rng(0x5eed_0f0f_1234_0001);
        for _ in 0..2_000 {
            let held = rng.amount();
            let den = rng.amount().max(1);
            let num = rng.amount() % (den + 1);
            let rep = session.open_bucket(Held::Amount(held), RESOURCE);
            let part = session
                .bucket_split(rep, U256::from_u128(num), U256::from_u128(den))
                .expect("a share at or under one");
            let share = session.bucket_amount(part).expect("a fungible edge");
            let rest = session.bucket_amount(rep).expect("a fungible edge");
            assert_eq!(
                share.checked_add(rest),
                Some(held),
                "split({num}/{den}) of {held} lost or made value"
            );
            assert!(share <= held);
        }
    }

    /// The dust falls to the bucket that was split, always: the share is
    /// the floor, so the remainder is what absorbs the truncation. That
    /// is the whole of the rounding policy, and it is a consequence of
    /// deriving one output rather than a direction anyone supplies.
    #[test]
    fn a_split_leaves_its_dust_with_the_remainder() {
        let set = declared(&[]);
        let mut session = session_over(MemoryStore::new(), &set);
        let rep = session.open_bucket(Held::Amount(10), RESOURCE);
        let part = session
            .bucket_split(rep, U256::from_u128(1), U256::from_u128(3))
            .expect("a third");
        assert_eq!(session.bucket_amount(part), Ok(3));
        assert_eq!(session.bucket_amount(rep), Ok(7));
    }

    /// The widest quantity there is, split by the finest share that is
    /// not zero: the product leaves the amount width entirely, which is
    /// what makes the operation the kernel's rather than a guest's.
    #[test]
    fn a_split_holds_a_product_the_amount_width_cannot() {
        let set = declared(&[]);
        let mut session = session_over(MemoryStore::new(), &set);
        let rep = session.open_bucket(Held::Amount(u128::MAX), RESOURCE);
        let part = session
            .bucket_split(
                rep,
                U256::from_u128(u128::MAX - 1),
                U256::from_u128(u128::MAX),
            )
            .expect("a share under one");
        let share = session.bucket_amount(part).expect("a fungible edge");
        let rest = session.bucket_amount(rep).expect("a fungible edge");
        assert_eq!(share.checked_add(rest), Some(u128::MAX));
        assert_eq!(rest, 1);
    }

    /// A share above one leaves a negative remainder, which denominates
    /// nothing — so it is refused rather than saturated. Saturating would
    /// answer `(everything, nothing)`, which is the kind of answer a
    /// caller builds on.
    #[test]
    fn a_share_above_one_is_refused_rather_than_saturated() {
        let set = declared(&[]);
        let mut session = session_over(MemoryStore::new(), &set);
        let rep = session.open_bucket(Held::Amount(100), RESOURCE);
        assert_eq!(
            session.bucket_split(rep, U256::from_u128(3), U256::from_u128(2)),
            Err(SessionTrap::ShareAboveOne)
        );
        assert_eq!(
            session.bucket_amount(rep),
            Ok(100),
            "a refused split moves nothing"
        );
    }

    /// A zero denominator is the empty pool's share, and it is a refusal
    /// rather than a trap in the arithmetic below it.
    #[test]
    fn a_split_by_nothing_is_refused() {
        let set = declared(&[]);
        let mut session = session_over(MemoryStore::new(), &set);
        let rep = session.open_bucket(Held::Amount(100), RESOURCE);
        assert_eq!(
            session.bucket_split(rep, U256::from_u128(1), U256::ZERO),
            Err(SessionTrap::Math(MathError::DivideByZero))
        );
    }

    /// A proportion cannot divide named instances: which ones would it
    /// take? The vocabulary refuses rather than picking.
    #[test]
    fn a_proportion_does_not_divide_an_instance_edge() {
        let set = declared(&[]);
        let mut session = session_over(MemoryStore::new(), &set);
        let rep = session.open_bucket(
            Held::Instances([1u128, 2, 3].into_iter().collect()),
            RESOURCE,
        );
        assert_eq!(
            session.bucket_split(rep, U256::from_u128(1), U256::from_u128(2)),
            Err(SessionTrap::WrongEdgeKind)
        );
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

    /// One cell holds one thing, judged where two expressions that
    /// evaluate onto it can no longer hide behind being different
    /// expressions.
    ///
    /// The publish gate compares target expressions, so a signature that
    /// spells one cell two ways passes it. What lands here is the
    /// evaluated key — and if a body held both handles over it, a balance
    /// written through the byte one and debited through the value one
    /// would be value from nowhere.
    #[test]
    fn one_cell_does_not_materialise_as_a_vault_and_a_byte_cell() {
        let write = Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Write {
                requires: Presence::Either,
            },
        };
        let materialise = |holds: &[Option<Address>]| {
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &declared(&[write]),
                &[write, write],
                holds,
                tx(1),
                env(),
                hash,
            )
            .map(|_| ())
        };

        // Two clauses on one leaf, one saying it holds value and one
        // saying nothing: the pair no handle is built for.
        assert_eq!(
            materialise(&[Some(RESOURCE), None]),
            Err(MaterializeError::MixedContents(write.target))
        );
        assert_eq!(
            materialise(&[None, Some(RESOURCE)]),
            Err(MaterializeError::MixedContents(write.target))
        );
        // Agreeing clauses are what a body that reads and writes one cell
        // declares, and both directions stand.
        assert!(materialise(&[Some(RESOURCE), Some(RESOURCE)]).is_ok());
        assert!(materialise(&[None, None]).is_ok());

        // A collection is the same statement over its entries: two
        // intervals of one collection are two targets, so the
        // disagreement is about the entries rather than about the slices
        // naming them.
        let interval = |hi| Effect {
            target: EffectTarget::Range {
                owner: Address::new([9; 31], AddressClass::Component),
                collection: CollectionId([4; 16]),
                lo: 0,
                hi,
                cap: 4,
            },
            mode: Mode::Write {
                requires: Presence::Either,
            },
        };
        let wide = interval(u128::MAX);
        let narrow = interval(10);
        assert_eq!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &declared(&[wide, narrow]),
                &[wide, narrow],
                &[Some(RESOURCE), None],
                tx(1),
                env(),
                hash,
            )
            .map(|_| ())
            .expect_err("one collection, two answers about its entries"),
            MaterializeError::MixedContents(narrow.target)
        );
    }

    #[test]
    fn the_reserved_rep_names_a_branch_that_was_not_declared() {
        // A guest is handed a handle for every clause its signature
        // declares, guarded-out ones included — an export's parameter
        // list is a function of its signature and cannot lose a
        // parameter to a branch. Touching that one is a body whose
        // control flow disagrees with the verdict it was given, and the
        // diagnostic is the whole value of naming it: nothing was
        // materialized here on purpose.
        let set = declared(&[Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Read,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        assert_eq!(
            session.read_cell(ABSENT_REP),
            Err(SessionTrap::UndeclaredBranch)
        );
        assert_eq!(
            session.range_count(ABSENT_REP),
            Err(SessionTrap::UndeclaredBranch)
        );
        assert_eq!(
            AbortReason::from(SessionTrap::UndeclaredBranch),
            AbortReason::UndeclaredBranch
        );
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
            mode: Mode::Write {
                requires: Presence::Either,
            },
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
            mode: Mode::Write {
                requires: Presence::Either,
            },
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
            mode: Mode::Write {
                requires: Presence::Either,
            },
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
            mode: Mode::Write {
                requires: Presence::Either,
            },
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
    fn a_re_materialized_page_is_charged_again() {
        // The write budget survives an invalidation, so the loop that
        // re-scans between writes is reachable; what stops it being free
        // is that each page costs what it lifts.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..4u128 {
            store
                .entry_write(owner, collection, order, vec![7; 10])
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
            mode: Mode::Write {
                requires: Presence::Either,
            },
        }]);
        let mut session = session_over(store, &set);

        assert_eq!(session.range_count(0), Ok(4));
        let page = SCAN_SEEK_BYTES + 4 * (AMOUNT_CELL_BYTES + 10);
        assert_eq!(session.take_scan_debt(), page);
        // Drained, and a memoized page is not scanned twice.
        assert_eq!(session.range_count(0), Ok(4));
        assert_eq!(session.take_scan_debt(), 0);
        // A write drops the page, and asking for it again buys another.
        assert_eq!(session.range_set(0, 0, vec![8; 10]), Ok(()));
        assert_eq!(session.range_count(0), Ok(4));
        assert_eq!(session.take_scan_debt(), page);
    }

    #[test]
    #[should_panic(expected = "without charging what it lifted")]
    fn finishing_still_owing_for_a_scan_is_a_defect() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            },
            mode: Mode::Write {
                requires: Presence::Either,
            },
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        session.range_count(0).unwrap();
        let _ = session.finish(Outcome::Completed { value: None }, 0);
    }

    #[test]
    fn a_take_reaches_every_instance_the_interval_declares() {
        // A holder past the cap keeps its later ids: the cap bounds the
        // entries a take may touch, never which of them it can name.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..100u128 {
            store
                .entry_write(owner, collection, order, vec![1])
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
            mode: Mode::Write {
                requires: Presence::Either,
            },
        }]);
        let mut session = session_holding(store, &set);

        // An id well past the first page of four.
        assert_eq!(session.range_take(0, &[90]), Ok(0));
        assert_eq!(session.bucket(0), Ok(Held::Instances([90].into())));
        // And one the collection does not hold still refuses.
        assert_eq!(
            session.range_take(0, &[500]),
            Err(SessionTrap::InstanceNotHeld(500))
        );
        // The cap is the budget it always was: three more distinct
        // entries fit, a fourth does not.
        assert!(session.range_take(0, &[91, 92, 93]).is_ok());
        assert_eq!(
            session.range_take(0, &[94]),
            Err(SessionTrap::WriteCapExceeded { cap: 4, order: 94 })
        );
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
                mode: Mode::Write {
                    requires: Presence::Either,
                },
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
                &holding(&ord(&set)),
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
                &holding(&ord(&set)),
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
                &holding(&ord(&set)),
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

    /// A merge of a bucket into itself is one bucket, and the kernel says
    /// so rather than adding a quantity to itself.
    ///
    /// Both engines' canonical ABIs refuse the call before it reaches
    /// here — an owned argument cannot be lifted out of a handle the same
    /// call is borrowing — so this is the kernel holding the invariant on
    /// its own account, where it does not depend on either of them.
    #[test]
    fn a_merge_of_a_bucket_into_itself_is_not_two_buckets() {
        let vault = key(0xB1);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();
        store.clear_log();
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Write {
                requires: Presence::Either,
            },
        }]);
        let mut session = session_holding(store, &set);

        let funds = session.write_take(0, 40).expect("the cell covers it");
        assert_eq!(
            session.bucket_put(funds, funds),
            Err(SessionTrap::UnknownHandle(funds)),
        );
        // And the take consumed it exactly once: the bucket is gone, not
        // doubled and not left standing.
        assert_eq!(
            session.bucket(funds),
            Err(SessionTrap::UnknownHandle(funds))
        );
    }

    /// Value a body neither credits nor hands back does not commit.
    ///
    /// The drop refusal only reaches a body that lets a handle go. One
    /// that keeps it says nothing to the ABI at all, so the debit would
    /// otherwise land and the value it produced reach nowhere.
    #[test]
    fn a_transaction_still_holding_value_does_not_commit() {
        let vault = key(0xB2);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();
        store.clear_log();
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Write {
                requires: Presence::Either,
            },
        }]);
        let mut session = session_holding(store, &set);

        let funds = session.write_take(0, 40).expect("the cell covers it");
        let (receipt, mut threaded) = session
            .finish(Outcome::Completed { value: None }, 7)
            .expect("finishes");
        assert_eq!(
            receipt.outcome,
            Outcome::UserError {
                reason: AbortReason::ValueDropped,
            },
        );
        // The debit is discarded with everything else the transaction
        // claimed, so the cell stands where it was.
        assert_eq!(
            decode_amount(&threaded.read(vault).unwrap().unwrap()),
            Ok(100)
        );
        assert!(receipt.delta.cells.is_empty());
        let _ = funds;
    }

    /// An emptied bucket is not value, so keeping one commits.
    ///
    /// What a split leaves behind is a live handle carrying nothing, and
    /// a body has no reason to put it anywhere. Refusing on liveness
    /// rather than on quantity would make every split need a drop.
    #[test]
    fn an_empty_bucket_left_standing_is_not_a_loss() {
        let vault = key(0xB3);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();
        store.clear_log();
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Write {
                requires: Presence::Either,
            },
        }]);
        let mut session = session_holding(store, &set);

        let funds = session.write_take(0, 40).expect("the cell covers it");
        let split = session.bucket_take(funds, 40).expect("the whole of it");
        session.write_put(0, split).expect("the credit lands");

        let (receipt, _) = session
            .finish(Outcome::Completed { value: None }, 7)
            .expect("finishes");
        assert_eq!(receipt.outcome, Outcome::Completed { value: None });
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
