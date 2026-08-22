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
//!
//! The four machines a session interleaves each live beside it:
//! [`materialize`] judges the declaration into the capability table,
//! [`buckets`] is the linearity ledger for value in flight, [`ranges`]
//! holds the interval scan cache and its budgets, and [`receipt`] folds
//! what committed.

mod buckets;
#[cfg(test)]
mod fixtures;
mod materialize;
mod ranges;
mod receipt;

use std::collections::BTreeSet;

use buckets::Buckets;
pub use buckets::Held;
use hyperscale_vm_effects::{ResourceKind, distinct_ids};
use hyperscale_vm_types::math::MathError;
use hyperscale_vm_types::{
    ABSENT_REP, AbortReason, Address, Drawn, EffectSet, ISSUER_REP, LEAF_KEY_BYTES, ResourceAddr,
    SEAL_MATURITY_EPOCHS, SEED_BYTES, SeedWindow, Seeded, SubstateKey, TxHash, encode_amount,
};
pub use materialize::{Capability, Interval, MaterializeError};
use ranges::Ranges;
pub use ranges::SCAN_SEEK_BYTES;
pub use receipt::{DeltaMap, FinishError, Receipt, StateDelta};

use crate::locality::Locality;
use crate::modes::{DeltaOp, ModeError, decode_amount};
use crate::overlay::OverlayStore;
use crate::store::{StoreError, WorkingStore};
use crate::supply::SupplyDelta;

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
        cell: ResourceAddr,
        /// What the value going into it carries.
        carried: ResourceAddr,
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
    /// A mint of the other kind than the grant's address commits: a
    /// fungible amount of a non-fungible resource, or the reverse.
    #[error("this grant does not issue what the operation creates")]
    WrongIssuanceKind,
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
            SessionTrap::WrongIssuanceKind => Self::WrongIssuanceKind,
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
use hyperscale_vm_types::{Event, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX};

/// Domain tag for a sealed draw.
///
/// Its own tag because the digest it produces is not the protocol hash
/// of anything a package could also ask for: a body that could compute
/// its own draw from parts it holds would not need the seal.
pub const DOMAIN_SEALED_DRAW: &[u8] = b"hyperscale/vm/sealed-draw";

/// The deterministic environment a transaction executes under.
#[derive(Clone, Debug)]
pub struct EnvInputs {
    /// The transaction clock in milliseconds.
    pub clock_ms: u64,
    /// The epoch this transaction executes in — what a seal records.
    pub epoch: u64,
    /// The transaction's randomness draw.
    pub randomness: [u8; 32],
    /// The epochs a sealed draw can resolve against, and the frontier
    /// separating one that has not happened from one that happened
    /// unusably.
    pub seeds: SeedWindow,
}

impl EnvInputs {
    /// An environment no seal can open: the clock and the draw, over a
    /// window nothing has folded into.
    ///
    /// For callers with no seal in sight. A consensus path states its
    /// window, on the same terms it states its clock — what a seal
    /// resolves to is an execution input, and one that defaulted would
    /// be a wrong answer nothing would catch.
    #[must_use]
    pub const fn unsealed(clock_ms: u64, randomness: [u8; 32]) -> Self {
        Self {
            clock_ms,
            epoch: 0,
            randomness,
            seeds: SeedWindow::unfolded(),
        }
    }
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
    /// The interval machinery: materialized scans, scan debt, write caps.
    ranges: Ranges,
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
    cell_resources: Vec<Option<ResourceAddr>>,
    /// The linearity ledger for value in flight; see [`buckets`].
    buckets: Buckets,
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
    issuance: Option<(ResourceAddr, ResourceKind)>,
    /// The runs this invocation has been lent, in the order the walk
    /// bound them; a run handle's rep is its index here.
    ///
    /// A rep space of its own beside the capability table's, because a
    /// run is not one capability — it is one site's whole expansion, and
    /// which capability an index reaches is the run's answer rather than
    /// the table's. The resource type a run is lent as is what tells the
    /// two spaces apart, on the same terms a bucket's rep is told from a
    /// cell's.
    runs: Vec<Vec<Option<u32>>>,
    /// Reservations already taken, by capability rep.
    ///
    /// A grant answers once. The read this replaces answered every time
    /// it was asked, so a body asking twice held two edges against one
    /// hold; taking is a question with one answer and this is what makes
    /// it so.
    taken: BTreeSet<u32>,
}

impl KernelSession {
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

    /// What the cell behind a capability holds, where it holds value.
    fn cell_resource(&self, rep: u32) -> Option<ResourceAddr> {
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
    fn value_of(&self, rep: u32) -> Result<ResourceAddr, SessionTrap> {
        self.cell_resource(rep)
            .ok_or(SessionTrap::BytesAsValue(rep))
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
        let carried = self.buckets.resource_of(funds)?;
        if cell == carried {
            Ok(())
        } else {
            Err(SessionTrap::WrongResource { cell, carried })
        }
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

    /// Lend one `for-each` site's expansion, answering the rep the run
    /// is reached at.
    ///
    /// Bound per invocation as the walk assembles the call's arguments,
    /// which is where the entries were resolved.
    pub fn bind_run(&mut self, entries: Vec<Option<u32>>) -> u32 {
        let rep = u32::try_from(self.runs.len()).unwrap_or(ABSENT_REP);
        self.runs.push(entries);
        rep
    }

    /// The run at `rep`.
    fn run(&self, rep: u32) -> Result<&[Option<u32>], SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.runs.get(index))
            .map(Vec::as_slice)
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// How many elements the site's loop mapped over.
    ///
    /// The element count rather than the count of expansions that fired,
    /// so two sites in one body agree on what an index means and a
    /// guarded one reads absent rather than shortening the walk.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] on a rep no run occupies.
    pub fn run_len(&self, rep: u32) -> Result<u32, SessionTrap> {
        Ok(u32::try_from(self.run(rep)?.len()).unwrap_or(u32::MAX))
    }

    /// Whether the site declared anything for the element at `index`.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn run_declared(&self, rep: u32, index: u32) -> Result<bool, SessionTrap> {
        Ok(self.run_entry(rep, index)?.is_some())
    }

    /// The capability the site declared for the element at `index`.
    ///
    /// An expansion whose guard did not fire answers [`ABSENT_REP`],
    /// which the operation it is handed to traps on by its own name —
    /// the same answer a guarded clause at top level already gives.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn run_at(&self, rep: u32, index: u32) -> Result<u32, SessionTrap> {
        Ok(self.run_entry(rep, index)?.unwrap_or(ABSENT_REP))
    }

    /// One entry of a run, refusing an index past its elements.
    fn run_entry(&self, rep: u32, index: u32) -> Result<Option<u32>, SessionTrap> {
        let entries = self.run(rep)?;
        usize::try_from(index)
            .ok()
            .and_then(|index| entries.get(index))
            .copied()
            .ok_or(SessionTrap::IndexOutOfBounds {
                index,
                count: entries.len(),
            })
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
        let (Capability::Amount(key) | Capability::AmountRead(key)) = self.capability(rep)? else {
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

    /// The draw the seal in this cell matures into.
    ///
    /// Everything the word is made of was fixed before the transaction
    /// that reads it: the seed of an epoch the seal named and the
    /// protocol's maturity put past it, and the key of the cell the
    /// handle names. Nothing about the attempt enters — not its hash,
    /// not its sender, not the block that carries it — so two attempts
    /// at one seal answer alike and abandoning one buys nothing.
    ///
    /// The cell's key is what separates two seals of one package. A
    /// nonce would put that choice in a body, where a package could mint
    /// itself as many candidate draws as it liked.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn open_seal(&self, rep: u32, epoch: u64) -> Result<Drawn, SessionTrap> {
        let Capability::Write(key) = self.capability(rep)? else {
            return Err(SessionTrap::WrongMode(rep));
        };
        Ok(match self.matured_seed(epoch) {
            Seeded::Pending => Drawn::Pending,
            Seeded::Expired => Drawn::Expired,
            Seeded::Ready(seed) => {
                let mut preimage =
                    Vec::with_capacity(DOMAIN_SEALED_DRAW.len() + SEED_BYTES + LEAF_KEY_BYTES);
                preimage.extend_from_slice(DOMAIN_SEALED_DRAW);
                preimage.extend_from_slice(&seed);
                preimage.extend_from_slice(&key.to_bytes());
                Drawn::Ready((self.hash_fn)(&preimage))
            }
        })
    }

    /// The other end of a write capability: the leaf ends rather than
    /// changing.
    ///
    /// What makes a cell's lifetime an ordinary one — created where the
    /// declaration required it absent, ended where the declaration
    /// required it present — so state a package stops needing stops
    /// being state.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_cell_clear(&mut self, rep: u32) -> Result<(), SessionTrap> {
        match self.capability(rep)? {
            Capability::Write(key) => {
                self.store.remove(key)?;
                Ok(())
            }
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
        let resource = self.issued(rep, ResourceKind::Fungible)?;
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
        let resource = self.issued(rep, ResourceKind::NonFungible)?;
        let named = distinct_ids(ids).ok_or(SessionTrap::MalformedIdSet)?;
        let instances: BTreeSet<u128> = named.into_iter().map(u128::from).collect();
        // An instance's supply is its existence: what a non-fungible
        // mints is a count, which is what its holdings are measured in.
        self.supply.mint(resource, instances.len() as u128)?;
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
        let Some((resource, _)) = self.issuance else {
            return Err(SessionTrap::IssuanceUngranted);
        };
        // A grant names one resource, so what it destroys is that one:
        // burning through another instance's grant would be destroying
        // value this invocation has no authority over.
        let carried = self.buckets.resource_of(funds)?;
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
    /// entering the next one takes it away again. The resource and its
    /// kind are the grant's whole content — what a body may bring into
    /// or out of existence is fixed before it runs, and there is no
    /// second one it could name.
    pub const fn grant_issuance(&mut self, resource: ResourceAddr, kind: ResourceKind) {
        self.issuance = Some((resource, kind));
    }

    /// The granted resource, held to the kind the operation creates.
    ///
    /// The grant's address commits its kind, so a mint of the other
    /// kind is not a variant of the resource — it is an operation on a
    /// resource this invocation was never granted.
    fn issued(&self, rep: u32, kind: ResourceKind) -> Result<ResourceAddr, SessionTrap> {
        if rep != ISSUER_REP {
            return Err(SessionTrap::UnknownHandle(rep));
        }
        let Some((resource, granted)) = self.issuance else {
            return Err(SessionTrap::IssuanceUngranted);
        };
        if granted != kind {
            return Err(SessionTrap::WrongIssuanceKind);
        }
        Ok(resource)
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

    /// The epoch this transaction executes in.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.env.epoch
    }

    /// The seed a seal written in `epoch` matures into.
    ///
    /// The offset is the whole of the maturity rule: what a seal
    /// commits to is a value that did not exist when it was written, and
    /// [`SEAL_MATURITY_EPOCHS`] is how far past the writing that
    /// becomes true.
    #[must_use]
    pub fn matured_seed(&self, epoch: u64) -> Seeded {
        self.env
            .seeds
            .at(epoch.saturating_add(SEAL_MATURITY_EPOCHS))
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_vm_types::{
        ABSENT_REP, AbortReason, Address, AddressClass, Drawn, Effect, EffectSet, EffectTarget,
        MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX, Mode, SEAL_MATURITY_EPOCHS,
        SEED_BYTES, SeedWindow, Seeded, SubstateKey, encode_amount,
    };

    use super::fixtures::{
        declared, env, key, session_for, session_holding, session_over, session_under, tx,
    };
    use super::{EnvInputs, SessionTrap};
    use crate::ledger::AmountLedger;
    use crate::overlay::OverlayStore;
    use crate::store::{MemoryStore, StoreError};

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
        // A read handle is not a write, a delta, a reserve, or an
        // interval.
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
    fn the_environment_reaches_the_guest_unchanged() {
        let session = session_over(MemoryStore::new(), &declared(&[]));
        assert_eq!(session.clock_ms(), env().clock_ms);
        assert_eq!(session.randomness(), env().randomness);
        assert_eq!(session.hash(&[1, 2, 3])[0], 3);
        assert!(session.capabilities().is_empty());
    }

    /// A seal resolves against the epoch two past the one it was
    /// written in, and the offset is the commitment: a seal cannot open
    /// onto a value that existed when it was written.
    #[test]
    fn a_seal_matures_two_epochs_past_its_own() {
        let seeds = SeedWindow::new(
            std::collections::BTreeMap::from([(6, [0x11; 32]), (8, [0x22; 32])]),
            Some(8),
        );
        let session = session_under(
            MemoryStore::new(),
            &declared(&[]),
            EnvInputs { seeds, ..env() },
        );

        assert_eq!(session.matured_seed(6), Seeded::Ready([0x22; 32]));
        assert_eq!(
            session.matured_seed(4),
            Seeded::Ready([0x11; 32]),
            "a seal reads the epoch it named, not the newest one folded"
        );
        assert_eq!(
            session.matured_seed(5),
            Seeded::Expired,
            "an epoch the host folded and will not stand behind is gone"
        );
        assert_eq!(
            session.matured_seed(7),
            Seeded::Pending,
            "a seal whose epoch has not been folded is a wait"
        );
    }

    /// A window with one usable seed, so a seal in `epoch` opens and
    /// nothing else does.
    fn sealed_env(epoch: u64) -> EnvInputs {
        EnvInputs {
            seeds: SeedWindow::new(
                std::collections::BTreeMap::from([(
                    epoch + SEAL_MATURITY_EPOCHS,
                    [0x5E; SEED_BYTES],
                )]),
                Some(epoch + SEAL_MATURITY_EPOCHS),
            ),
            ..env()
        }
    }

    fn writing(at: SubstateKey) -> EffectSet {
        declared(&[Effect {
            target: EffectTarget::Point(at),
            mode: Mode::Write,
        }])
    }

    /// The property the whole seal exists for: what a seal opens onto is
    /// a function of committed state and of a seed rolled after it was
    /// written, and of nothing about the attempt that reads it.
    ///
    /// Two transactions, two hashes, one seal — one word. A derivation
    /// that reached for the transaction would answer twice here, and
    /// answering twice is what lets a loser abandon an attempt and try
    /// again for a different outcome.
    #[test]
    fn one_seal_answers_one_word_however_many_attempts_ask() {
        let set = writing(key(1));
        let words: Vec<_> = [tx(0xA1), tx(0xB2)]
            .into_iter()
            .map(|tx| {
                session_for(MemoryStore::new(), &set, sealed_env(9), tx)
                    .open_seal(0, 9)
                    .expect("a write handle holds a seal")
            })
            .collect();

        assert!(matches!(words[0], Drawn::Ready(_)));
        assert_eq!(words[0], words[1], "the attempt is not an input");
    }

    /// Two cells, one epoch, two words. The cell's key is what separates
    /// a package's draws, so a package that wants a second one holds a
    /// second cell — and cannot mint itself candidates to choose among
    /// by naming a nonce.
    #[test]
    fn two_sealed_cells_of_one_epoch_draw_apart() {
        let first = session_for(MemoryStore::new(), &writing(key(1)), sealed_env(9), tx(1))
            .open_seal(0, 9)
            .expect("a write handle holds a seal");
        let second = session_for(MemoryStore::new(), &writing(key(2)), sealed_env(9), tx(1))
            .open_seal(0, 9)
            .expect("a write handle holds a seal");

        assert!(matches!(first, Drawn::Ready(_)));
        assert_ne!(first, second);
    }

    /// A seal is opened through the handle that holds it, so a
    /// capability that is not an exclusive write has no draw to give.
    #[test]
    fn a_seal_opens_only_through_the_cell_that_holds_it() {
        let set = declared(&[Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Read,
        }]);
        let session = session_under(MemoryStore::new(), &set, sealed_env(9));
        assert_eq!(session.open_seal(0, 9), Err(SessionTrap::WrongMode(0)));
    }

    /// The two ways a seal fails to open are two answers, because a
    /// package does different things with them: wait, or close again.
    #[test]
    fn an_early_seal_waits_where_a_lapsed_one_is_over() {
        let session = session_under(MemoryStore::new(), &writing(key(1)), sealed_env(9));
        assert_eq!(session.open_seal(0, 10), Ok(Drawn::Pending));
        assert_eq!(session.open_seal(0, 8), Ok(Drawn::Expired));
    }

    #[test]
    fn emission_refuses_outside_an_invocation_and_past_its_caps() {
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
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

    /// The grant is a quantity and it leaves the kernel once: a second
    /// take of one reservation would be a second edge against one hold.
    #[test]
    fn a_reservation_is_taken_once() {
        let vault = key(6);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec());
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Reserve { amount: 40 },
        }]);
        let mut session = session_holding(store, &set);

        let funds = session.reserve_take(0).expect("the grant is held");
        assert_eq!(session.reserve_take(0), Err(SessionTrap::ReservationTaken));
        // The refusal minted nothing: the one edge stands as it was.
        assert_eq!(session.bucket_amount(funds), Ok(40));
    }

    #[test]
    fn judging_refuses_the_same_pair_twice() {
        let vault = key(5);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec());
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
