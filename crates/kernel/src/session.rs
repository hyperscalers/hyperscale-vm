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
mod permit;
mod ranges;
mod receipt;

use std::collections::BTreeSet;

use buckets::Buckets;
pub use buckets::Held;
use hyperscale_vm_effects::{ResourceKind, distinct_ids};
use hyperscale_vm_types::math::MathError;
use hyperscale_vm_types::{
    ABSENT_REP, AbortReason, Address, Drawn, EffectSet, EffectTarget, LEAF_KEY_BYTES, ResourceAddr,
    SEAL_MATURITY_EPOCHS, SEED_BYTES, SeedWindow, Seeded, SubstateKey, TxHash,
};
pub use materialize::{Capability, Interval, MaterializeError};
pub use permit::{Op, permits};
use ranges::Ranges;
pub use ranges::SCAN_SEEK_BYTES;
pub use receipt::{DeltaMap, FinishError, Receipt, StateDelta};

use crate::ledger::AmountLedger;
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
    /// A rep whose capability does not grant the operation.
    ///
    /// Carries both halves because the diagnostic is the whole value: a
    /// rep alone says a body disagreed with its declaration without
    /// saying how, and this is the only signal a body reaching past its
    /// declaration gets.
    #[error(
        "the handle at site {site} element {element} holds {}, which does not grant {}",
        permit::describe(held),
        attempted.describe()
    )]
    WrongMode {
        /// The site the operation named.
        site: u32,
        /// Which element of it.
        element: u32,
        /// What the declaration materialized there.
        held: Capability,
        /// What the body tried to do through it.
        attempted: Op,
    },
    /// A cell resealed while its standing seal can still open.
    ///
    /// A seed is public the moment it rolls, and so is the word derived
    /// from it — so replacing a seal that has matured, or one that is
    /// merely early, is a re-roll of a draw somebody can already read.
    /// Only a seal that will never open may be replaced.
    #[error("handle {0} names a cell whose seal has not lapsed")]
    SealStanding(u32),
    /// A cell opened as a seal that holds something else.
    ///
    /// Only the kernel writes a seal, so the bytes under one are its own
    /// eight — unless a guest wrote over them through the same write
    /// handle, which is its declaration and its body disagreeing about
    /// what the leaf is for.
    #[error("handle {0} names a cell that holds no seal")]
    NotASeal(u32),
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
    #[error(
        "the handle at site {site} element {element} names a cell that denominates nothing, \
         so no value moves through it"
    )]
    BytesAsValue {
        /// The site the operation named.
        site: u32,
        /// Which element of it.
        element: u32,
    },
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
            SessionTrap::WrongMode { .. } => Self::HandleWrongMode,
            SessionTrap::NotASeal(_) => Self::MalformedSeal,
            SessionTrap::SealStanding(_) => Self::SealStanding,
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
            SessionTrap::BadAmountCell(_) => Self::MalformedAmountCell,
            SessionTrap::CellUnderflow => Self::CellUnderflow,
            SessionTrap::CellOverflow => Self::CellOverflow,
            SessionTrap::NoInvocation => Self::EmissionOutsideInvocation,
            SessionTrap::EventTypeOutOfRange(_) => Self::EventTypeOutOfRange,
            SessionTrap::TooManyEvents => Self::EventCountExceeded,
            SessionTrap::EventPayloadTooLarge(_) => Self::EventPayloadTooLarge,
            SessionTrap::ShareAboveOne => Self::ShareAboveOne,
            SessionTrap::WrongResource { .. } => Self::WrongResource,
            SessionTrap::BytesAsValue { .. } => Self::BytesAsValue,
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

/// The epoch a seal cell's bytes record.
///
/// Eight little-endian bytes and nothing else, because the kernel is the
/// only writer: anything of another width is a package that wrote over
/// its own seal through the same handle it opens with.
fn sealed_epoch(rep: u32, held: &[u8]) -> Result<u64, SessionTrap> {
    held.try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| SessionTrap::NotASeal(rep))
}

/// The deterministic environment a transaction executes under.
#[derive(Clone, Debug)]
pub struct EnvInputs {
    /// The transaction clock in milliseconds.
    pub clock_ms: u64,
    /// The epoch this transaction executes in — what a seal records.
    pub epoch: u64,
    /// The epochs a sealed draw can resolve against, and the frontier
    /// separating one that has not happened from one that happened
    /// unusably.
    pub seeds: SeedWindow,
}

impl EnvInputs {
    /// An environment no seal can open: a clock, over a window nothing
    /// has folded into.
    ///
    /// For callers with no seal in sight. A consensus path states its
    /// window, on the same terms it states its clock — what a seal
    /// resolves to is an execution input, and one that defaulted would
    /// be a wrong answer nothing would catch.
    #[must_use]
    pub const fn unsealed(clock_ms: u64) -> Self {
        Self {
            clock_ms,
            epoch: 0,
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
    /// Every site this invocation can act through, flattened: one entry
    /// per element of each site, in the order they were bound.
    ///
    /// An entry names a position in [`KernelSession::table`], or nothing
    /// where the site's guard did not fire for that element.
    entries: Vec<Option<u32>>,
    /// Where each site's entries start, and how many it has; a site
    /// handle's rep is its index here.
    ///
    /// Materialization seeds one width-one site per capability, in table
    /// order, so **site `n` element 0 is capability `n`** — which is what
    /// lets a session be acted through the moment it exists, rather than
    /// only after a walk has bound something. Sites a `for-each` needs
    /// are appended past the seeded ones.
    sites: Vec<(u32, u32)>,
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
    fn cell_resource(&self, site: u32, element: u32) -> Option<ResourceAddr> {
        self.resource_at(self.entry(site, element).ok()??)
    }

    /// What the cell behind one capability holds, by its position in the
    /// table — for the kernel's own walks, which have no site in hand.
    fn resource_at(&self, rep: u32) -> Option<ResourceAddr> {
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
    fn value_of(&self, site: u32, element: u32) -> Result<ResourceAddr, SessionTrap> {
        self.cell_resource(site, element)
            .ok_or(SessionTrap::BytesAsValue { site, element })
    }

    /// Judge a credit: the value going into a cell is the resource that
    /// cell holds, or it does not go in.
    ///
    /// One comparison with nothing to skip. Both sides are known by
    /// construction — a cell a movement reaches was denominated by the
    /// declaration, and a bucket carries what it was made from — so the
    /// question is only whether they agree.
    fn judge_credit(&self, site: u32, element: u32, funds: u32) -> Result<(), SessionTrap> {
        let cell = self.value_of(site, element)?;
        let carried = self.buckets.resource_of(funds)?;
        if cell == carried {
            Ok(())
        } else {
            Err(SessionTrap::WrongResource { cell, carried })
        }
    }

    /// The capability one element of a site names.
    ///
    /// An element the site's guard did not fire for names none, which is
    /// a body whose control flow disagrees with the verdict it was
    /// handed — named rather than folded into an unknown handle because
    /// the diagnostic is the whole value: nothing was materialized here
    /// on purpose.
    fn at(&self, site: u32, element: u32) -> Result<Capability, SessionTrap> {
        let rep = self.rep_at(site, element)?;
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.table.get(index))
            .copied()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// Where in the table the capability one element names sits.
    ///
    /// The identity a per-capability budget is kept under: two handle
    /// parameters may name one clause, so the site that reached it is
    /// not what a rule about the declaration may key on.
    fn rep_at(&self, site: u32, element: u32) -> Result<u32, SessionTrap> {
        self.entry(site, element)?
            .ok_or(SessionTrap::UndeclaredBranch)
    }

    /// The capability at `rep`, held to the operation it is about to
    /// perform.
    ///
    /// The one place permission is decided. Every operation reaches its
    /// capability through here, so an operation added later cannot act
    /// through a mode that never granted it — there is no other way to
    /// resolve a rep into something to act on.
    fn acting(&self, site: u32, element: u32, attempted: Op) -> Result<Capability, SessionTrap> {
        let held = self.at(site, element)?;
        if permits(&held, attempted) {
            Ok(held)
        } else {
            Err(SessionTrap::WrongMode {
                site,
                element,
                held,
                attempted,
            })
        }
    }

    /// The cell a point operation acts on, once its capability has been
    /// held to it.
    ///
    /// The interval arms are unreachable — no operation admitting an
    /// interval resolves through here — and answer as the refusal they
    /// would be rather than as a panic, on the terms every other handle
    /// refusal does.
    fn acting_key(
        &self,
        site: u32,
        element: u32,
        attempted: Op,
    ) -> Result<SubstateKey, SessionTrap> {
        match self.acting(site, element, attempted)? {
            Capability::Read(key)
            | Capability::Write(key)
            | Capability::Amount(key)
            | Capability::AmountRead(key)
            | Capability::Delta(key)
            | Capability::Credit(key)
            | Capability::Reserve { key, .. } => Ok(key),
            held @ (Capability::RangeRead(_)
            | Capability::RangeWrite(_)
            | Capability::InstanceRange(_)) => Err(SessionTrap::WrongMode {
                site,
                element,
                held,
                attempted,
            }),
        }
    }

    /// Lend one declared site, answering the rep it is reached at.
    ///
    /// One entry per element, in the order the walk resolved them: a
    /// plain access is a site of one, and a `for-each` site is as wide
    /// as the collection its loop mapped over.
    ///
    /// Always appended, never matched against the seeded sites: a site
    /// the walk binds carries what the *declaration* resolved, which for
    /// a guarded-out clause is an absence no capability stands behind.
    pub fn bind_site(&mut self, entries: Vec<Option<u32>>) -> u32 {
        let rep = u32::try_from(self.sites.len()).unwrap_or(u32::MAX);
        let start = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        let len = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        self.entries.extend(entries);
        self.sites.push((start, len));
        rep
    }

    /// The entries the site at `rep` covers.
    fn site(&self, rep: u32) -> Result<&[Option<u32>], SessionTrap> {
        let (start, len) = usize::try_from(rep)
            .ok()
            .and_then(|index| self.sites.get(index))
            .copied()
            .ok_or(SessionTrap::UnknownHandle(rep))?;
        let start = start as usize;
        self.entries
            .get(start..start + len as usize)
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// How many elements the site covers.
    ///
    /// The element count rather than the count of expansions that fired,
    /// so two sites in one body agree on what an index means and a
    /// guarded one reads absent rather than shortening the walk. A plain
    /// access answers one, declared or not.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] on a rep no site occupies.
    pub fn site_len(&self, rep: u32) -> Result<u32, SessionTrap> {
        Ok(u32::try_from(self.site(rep)?.len()).unwrap_or(u32::MAX))
    }

    /// Whether the site declared anything for the element at `index`.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn site_declared(&self, rep: u32, index: u32) -> Result<bool, SessionTrap> {
        Ok(self.entry(rep, index)?.is_some())
    }

    /// The capability the site declared for the element at `index`, as
    /// the rep every other operation takes.
    ///
    /// An element whose guard did not fire answers [`ABSENT_REP`], which
    /// the operation it is handed to traps on by its own name.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn site_at(&self, rep: u32, index: u32) -> Result<u32, SessionTrap> {
        Ok(self.entry(rep, index)?.unwrap_or(ABSENT_REP))
    }

    /// One entry of a site, refusing an index past its elements.
    fn entry(&self, rep: u32, index: u32) -> Result<Option<u32>, SessionTrap> {
        if rep == ABSENT_REP {
            return Err(SessionTrap::UndeclaredBranch);
        }
        let entries = self.site(rep)?;
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

    /// Whether the target a declared read names holds anything.
    ///
    /// Presence rather than contents, because that is the whole of what
    /// a credential asks — and for a value cell the two agree, since a
    /// balance reaching zero deletes its leaf. The same read
    /// materialization performs, so a rule mixing presence with evidence
    /// gets the same answer wherever the mix sends it.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`] the store raises.
    pub fn declared_present(&mut self, target: EffectTarget) -> Result<bool, SessionTrap> {
        Ok(materialize::occupied(&mut self.store, target)?)
    }

    /// The bytes this cell holds; empty if absent.
    ///
    /// One read for both byte modes. What the exclusive mode adds is the
    /// writes, so the question a fresh read asks and the question a hold
    /// asks are the same question with the same answer.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn cell_get(&mut self, site: u32, element: u32) -> Result<Vec<u8>, SessionTrap> {
        let key = self.acting_key(site, element, Op::Read)?;
        Ok(self.store.read(key)?.unwrap_or_default())
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
    pub fn amount_cell_balance(&mut self, site: u32, element: u32) -> Result<u128, SessionTrap> {
        let key = self.acting_key(site, element, Op::Balance)?;
        self.amount_cell(key)
    }

    /// The write half of a write capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_cell_set(
        &mut self,
        site: u32,
        element: u32,
        value: Vec<u8>,
    ) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Write)?;
        Ok(self.store.write(key, value)?)
    }

    /// Seal this cell on the epoch now running.
    ///
    /// The kernel writes the epoch rather than taking one, and that is
    /// the whole of the commitment. A body that named its own would name
    /// an epoch already rolled, and open onto a word it could have
    /// computed before deciding to seal — so what a seal commits to
    /// would be whatever its writer already knew.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn seal(&mut self, site: u32, element: u32) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Seal)?;
        // A leaf already under a seal takes another only where the
        // standing one will never open. A matured seed is public, and so
        // is the word it produces, so replacing a seal that can still
        // open is a re-roll of a draw somebody has already read — and a
        // package left to enforce that itself would be a package one
        // careless method away from offering the re-roll.
        if let Some(held) = self.store.read(key)?
            && !matches!(
                self.matured_seed(sealed_epoch(site, &held)?),
                Seeded::Expired
            )
        {
            return Err(SessionTrap::SealStanding(site));
        }
        Ok(self
            .store
            .write(key, self.env.epoch.to_le_bytes().to_vec())?)
    }

    /// The draw the seal in this cell matures into.
    ///
    /// Everything the word is made of was fixed before the transaction
    /// that reads it: the seed of the epoch the cell's own seal records
    /// with the protocol's maturity put past it, and the key of the cell
    /// the handle names. Nothing about the attempt enters — not its
    /// hash, not its sender, not the block that carries it — so two
    /// attempts at one seal answer alike and abandoning one buys
    /// nothing.
    ///
    /// The cell's key is what separates two seals of one package. A
    /// nonce would put that choice in a body, where a package could mint
    /// itself as many candidate draws as it liked.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including [`SessionTrap::NotASeal`] for a
    /// leaf a guest wrote its own bytes over.
    pub fn open_seal(&mut self, site: u32, element: u32) -> Result<Drawn, SessionTrap> {
        let key = self.acting_key(site, element, Op::OpenSeal)?;
        let held = self.store.read(key)?.unwrap_or_default();
        let epoch = sealed_epoch(site, &held)?;
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
    pub fn write_cell_clear(&mut self, site: u32, element: u32) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Clear)?;
        self.store.remove(key)?;
        Ok(())
    }

    /// Credit a delta capability with no bucket behind the credit.
    ///
    /// Fixtures only, and gated so it stays that way: value a
    /// transaction hands a cell comes out of the bucket table, and a
    /// credit that skipped it is value from nowhere. Production reaches
    /// the same queue through [`Self::cell_put`], which consumes an
    /// edge to make the credit.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    #[cfg(any(test, feature = "testing"))]
    pub fn delta_add(&mut self, site: u32, element: u32, amount: u128) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Put)?;
        Ok(self.store.queue_delta(key, DeltaOp::Add(amount))?)
    }

    /// Debit a delta capability without producing the edge for it.
    ///
    /// Fixtures only, on the terms [`Self::delta_add`] states.
    /// Production reaches the same queue through [`Self::cell_take`],
    /// which hands the debit out as a bucket.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    #[cfg(any(test, feature = "testing"))]
    pub fn delta_sub(&mut self, site: u32, element: u32, amount: u128) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Take)?;
        Ok(self.store.queue_delta(key, DeltaOp::Sub(amount))?)
    }

    /// The reserved amount behind a reserve capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn reserve_amount(&mut self, site: u32, element: u32) -> Result<u128, SessionTrap> {
        self.reserved(site, element, Op::ReservedAmount)
    }

    /// The grant a reservation carries, held to the operation asking.
    ///
    /// The clause's own declared amount, not the folded hold: two
    /// reservations on one cell share a single held total, and a guest
    /// asking about its grant means its own share of it. The hold is
    /// still consulted — a capability whose hold never materialized is a
    /// defect whatever amount it declared.
    fn reserved(&self, site: u32, element: u32, attempted: Op) -> Result<u128, SessionTrap> {
        let Capability::Reserve { key, amount } = self.acting(site, element, attempted)? else {
            return Err(SessionTrap::ReservationMissing);
        };
        self.store
            .held_reservation(key, self.tx)
            .map(|_| amount)
            .ok_or(SessionTrap::ReservationMissing)
    }

    /// Debit `amount` from this cell and hand the value out as a bucket.
    ///
    /// What the pairing buys, in either mode, is that the amount debited
    /// and the amount now in flight are one number the body never got to
    /// write twice. When the debit is refused differs: the exclusive hold
    /// performs the read-modify-write and refuses an over-take here,
    /// where the commutative movement queues and leaves the question to
    /// the fold.
    ///
    /// Either way it is what the cell holds, not what it has free. A
    /// reservation standing on the cell is another transaction's doing
    /// and nothing this body can see, so crossing one is judged at the
    /// fold with every other movement's floor — where it is priced as
    /// the lost race it is, rather than as this body's arithmetic.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn cell_take(&mut self, site: u32, element: u32, amount: u128) -> Result<u32, SessionTrap> {
        // A credit gave up this direction, which is why the table admits
        // it to the credit and not to the debit.
        let held = self.acting(site, element, Op::Take)?;
        let resource = self.value_of(site, element)?;
        let key = match held {
            // The exclusive hold performs the read-modify-write, so a
            // debit past what the cell holds is refused at the call.
            Capability::Amount(key) => {
                self.amount_cell(key)?
                    .checked_sub(amount)
                    .ok_or(SessionTrap::CellUnderflow)?;
                key
            }
            // The commutative movement queues, so whether the cell
            // covered it is the fold's question and an over-take is
            // infeasible at settle rather than a refusal here.
            Capability::Delta(key) => key,
            held => {
                return Err(SessionTrap::WrongMode {
                    site,
                    element,
                    held,
                    attempted: Op::Take,
                });
            }
        };
        self.store.queue_delta(key, DeltaOp::Sub(amount))?;
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// Credit this cell with what the bucket at `funds` carries.
    ///
    /// The bucket is consumed, so the credit and the value that crossed
    /// are one number and there is no second one to disagree with.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn cell_put(&mut self, site: u32, element: u32, funds: u32) -> Result<(), SessionTrap> {
        // Nothing is consumed until everything is judged. A refusal
        // aborts the whole transaction, so no state would escape either
        // way; what the ordering keeps true is that the kernel is never
        // holding a credit it did not make, which is the property the
        // bucket table exists to state.
        let held = self.acting(site, element, Op::Put)?;
        self.judge_credit(site, element, funds)?;
        let amount = self.bucket_amount(funds)?;
        let key = match held {
            // The exclusive hold performs the read-modify-write, so a
            // credit past the width an amount has is refused at the call.
            Capability::Amount(key) => {
                self.amount_cell(key)?
                    .checked_add(amount)
                    .ok_or(SessionTrap::CellOverflow)?;
                key
            }
            // A credit answers this and a delta answers it too: what the
            // narrower mode gave up is the other direction, not this one.
            Capability::Delta(key) | Capability::Credit(key) => key,
            held => {
                return Err(SessionTrap::WrongMode {
                    site,
                    element,
                    held,
                    attempted: Op::Put,
                });
            }
        };
        self.store.queue_delta(key, DeltaOp::Add(amount))?;
        self.take_bucket(funds).map(|_| ())
    }

    /// A declared cell's contents as an amount, as this transaction has
    /// left it; an absent cell is zero.
    fn amount_cell(&mut self, key: SubstateKey) -> Result<u128, SessionTrap> {
        let cell = self.store.read(key)?.unwrap_or_default();
        let committed = if cell.is_empty() {
            0
        } else {
            decode_amount(&cell).map_err(|_| SessionTrap::BadAmountCell(key))?
        };
        Ok(self.store.with_queued(key, committed)?)
    }

    /// Create `amount` of what this invocation issues, as a bucket.
    ///
    /// The one bucket with no cell behind it. What an invocation may
    /// issue is its own grant, read off the outputs its declaration
    /// names, so there is nothing for a body to hold and nothing for it
    /// to name.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a mint against a grant this
    /// invocation was never given.
    pub fn mint(&mut self, amount: u128) -> Result<u32, SessionTrap> {
        let resource = self.issued(ResourceKind::Fungible)?;
        self.supply.mint(resource, amount)?;
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// Create the named instances of what this invocation issues.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a mint against a grant this
    /// invocation was never given.
    pub fn mint_instances(&mut self, ids: &[u64]) -> Result<u32, SessionTrap> {
        let resource = self.issued(ResourceKind::NonFungible)?;
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
    pub fn burn(&mut self, funds: u32) -> Result<(), SessionTrap> {
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
    fn issued(&self, kind: ResourceKind) -> Result<ResourceAddr, SessionTrap> {
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
    pub fn reserve_take(&mut self, site: u32, element: u32) -> Result<u32, SessionTrap> {
        let amount = self.reserved(site, element, Op::TakeReserved)?;
        let resource = self.value_of(site, element)?;
        // Once per capability rather than once per site: two handle
        // parameters may name one clause, and the grant leaves the
        // kernel once whichever of them asks.
        let rep = self.site_at(site, element)?;
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
        ABSENT_REP, AbortReason, Address, AddressClass, CollectionId, Drawn, Effect, EffectSet,
        EffectTarget, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX, Mode,
        SEAL_MATURITY_EPOCHS, SEED_BYTES, SeedWindow, Seeded, SubstateKey, encode_amount,
    };

    use super::fixtures::{
        declared, env, key, session_for, session_holding, session_over, session_under, tx,
    };
    use super::{Capability, EnvInputs, Interval, KernelSession, Op, SessionTrap, TxHash, permits};
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
        assert_eq!(session.cell_get(7, 0), Err(SessionTrap::UnknownHandle(7)));
        assert_eq!(
            session.range_count(7, 0),
            Err(SessionTrap::UnknownHandle(7))
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
            session.cell_get(ABSENT_REP, 0),
            Err(SessionTrap::UndeclaredBranch)
        );
        assert_eq!(
            session.range_count(ABSENT_REP, 0),
            Err(SessionTrap::UndeclaredBranch)
        );
        assert_eq!(
            AbortReason::from(SessionTrap::UndeclaredBranch),
            AbortReason::UndeclaredBranch
        );
    }

    /// Every mode the kernel materializes, one of each.
    ///
    /// Built rather than materialized from a declaration: what is under
    /// test is what a capability grants, and reaching each of the ten
    /// through a signature that produces it would test the materializer
    /// instead.
    fn every_capability() -> [Capability; 10] {
        let interval = Interval {
            owner: Address::new([9; 31], AddressClass::Component),
            collection: CollectionId([4; 16]),
            lo: 0,
            hi: 100,
            cap: 8,
        };
        [
            Capability::Read(key(1)),
            Capability::Write(key(1)),
            Capability::Amount(key(1)),
            Capability::AmountRead(key(1)),
            Capability::Delta(key(1)),
            Capability::Credit(key(1)),
            Capability::Reserve {
                key: key(1),
                amount: 5,
            },
            Capability::RangeRead(interval),
            Capability::RangeWrite(interval),
            Capability::InstanceRange(interval),
        ]
    }

    /// A session holding exactly `held`, reachable at rep zero.
    ///
    /// The capability and the site that reaches it are installed
    /// together, which is the invariant materialization keeps: a
    /// capability nothing can be acted through is not a session state
    /// any declaration produces.
    fn holding(held: Capability) -> KernelSession {
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
        session.table = vec![held];
        session.entries = vec![Some(0)];
        session.sites = vec![(0, 1)];
        session
    }

    /// Perform `op` through the entry point that carries it, at rep 0.
    ///
    /// The arguments are whatever reaches the permission check; an
    /// operation the capability grants may still fail for a reason of
    /// its own, which is why the matrix asks only whether the refusal
    /// was a mode refusal.
    fn attempt(session: &mut KernelSession, op: Op) -> Result<(), SessionTrap> {
        match op {
            Op::Read => session.cell_get(0, 0).map(|_| ()),
            Op::Write => session.write_cell_set(0, 0, vec![1]),
            Op::Clear => session.write_cell_clear(0, 0),
            Op::Seal => session.seal(0, 0),
            Op::OpenSeal => session.open_seal(0, 0).map(|_| ()),
            Op::Balance => session.amount_cell_balance(0, 0).map(|_| ()),
            Op::Take => session.cell_take(0, 0, 1).map(|_| ()),
            Op::Put => session.cell_put(0, 0, 0),
            Op::ReservedAmount => session.reserve_amount(0, 0).map(|_| ()),
            Op::TakeReserved => session.reserve_take(0, 0).map(|_| ()),
            Op::ReadEntries => session.range_count(0, 0).map(|_| ()),
            Op::WriteEntries => session.range_set(0, 0, 0, vec![1]),
            Op::MoveInstances => session.range_take(0, 0, &[1]).map(|_| ()),
        }
    }

    /// The whole of what the kernel permits, asked through the entry
    /// points a guest reaches rather than of the table alone: a row the
    /// table admits and the operation refuses anyway would pass a test
    /// of `permits` by itself.
    #[test]
    fn every_capability_grants_exactly_what_the_table_says() {
        for held in every_capability() {
            for op in Op::ALL {
                let mut session = holding(held);
                let refused = matches!(
                    attempt(&mut session, op),
                    Err(SessionTrap::WrongMode { .. })
                );
                assert_eq!(
                    refused,
                    !permits(&held, op),
                    "{held:?} against {op:?}: refused_as_wrong_mode={refused}"
                );
            }
        }
    }

    /// And a refusal says which mode was held and what was asked of it,
    /// because it is the only signal a body reaching past its own
    /// declaration gets.
    #[test]
    fn a_mode_refusal_names_both_halves() {
        let mut session = holding(Capability::Read(key(1)));
        assert_eq!(
            session.write_cell_set(0, 0, vec![1]),
            Err(SessionTrap::WrongMode {
                site: 0,
                element: 0,
                held: Capability::Read(key(1)),
                attempted: Op::Write,
            })
        );
        assert_eq!(
            session
                .write_cell_set(0, 0, vec![1])
                .unwrap_err()
                .to_string(),
            "the handle at site 0 element 0 holds a fresh read, which does not grant replace the \
             cell's bytes"
        );
    }

    #[test]
    fn the_environment_reaches_the_guest_unchanged() {
        let session = session_over(MemoryStore::new(), &declared(&[]));
        assert_eq!(session.clock_ms(), env().clock_ms);
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

    /// A window with one usable seed, so a seal written in `epoch`
    /// opens and nothing else does.
    fn sealed_env(epoch: u64) -> EnvInputs {
        EnvInputs {
            epoch,
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

    /// A session over one written cell, sealed in the epoch its own
    /// environment is running.
    fn sealed_session(set: &EffectSet, env: EnvInputs, tx: TxHash) -> KernelSession {
        let mut session = session_for(MemoryStore::new(), set, env, tx);
        session.seal(0, 0).expect("a write handle takes a seal");
        session
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
                sealed_session(&set, sealed_env(9), tx)
                    .open_seal(0, 0)
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
        let first = sealed_session(&writing(key(1)), sealed_env(9), tx(1))
            .open_seal(0, 0)
            .expect("a write handle holds a seal");
        let second = sealed_session(&writing(key(2)), sealed_env(9), tx(1))
            .open_seal(0, 0)
            .expect("a write handle holds a seal");

        assert!(matches!(first, Drawn::Ready(_)));
        assert_ne!(first, second);
    }

    /// The epoch a seal records is the kernel's, not a body's.
    ///
    /// A body that chose it could name an epoch already rolled — whose
    /// seed is public, and whose word it could therefore compute before
    /// deciding to seal at all. What the cell holds is the running
    /// epoch and nothing a guest handed over.
    #[test]
    fn a_seal_records_the_epoch_the_kernel_is_running() {
        let mut session = sealed_session(&writing(key(1)), sealed_env(9), tx(1));
        assert_eq!(
            session.cell_get(0, 0),
            Ok(9u64.to_le_bytes().to_vec()),
            "the leaf holds the running epoch"
        );

        // The same cell written over by hand, naming an epoch whose seed
        // is already rolled: the derivation reads the leaf, so this is
        // the only way to reach one — and it is a package's declaration
        // and body disagreeing about what the leaf is for.
        session
            .write_cell_set(0, 0, vec![0xFF; 3])
            .expect("a write handle sets");
        assert_eq!(session.open_seal(0, 0), Err(SessionTrap::NotASeal(0)));
    }

    /// A lapsed seal is the one a package may replace, and the only
    /// one.
    ///
    /// The word a matured seal opens onto is public the moment its seed
    /// rolls, so a package that could take a second seal over one that
    /// still answers would be offering a re-roll of a draw somebody has
    /// already read. A seal that will never open is the case where
    /// there is nothing to re-roll.
    #[test]
    fn only_a_lapsed_seal_gives_way_to_another() {
        let set = writing(key(1));

        // Standing, and matured: the word is there to be read, so the
        // cell keeps the seal that answers it.
        let mut ready = sealed_session(&set, sealed_env(9), tx(1));
        assert_eq!(ready.seal(0, 0), Err(SessionTrap::SealStanding(0)));
        assert!(matches!(ready.open_seal(0, 0), Ok(Drawn::Ready(_))));

        // Standing, and early: nothing to read yet, and nothing to gain
        // by waiting for a different one.
        let mut early = sealed_session(
            &set,
            EnvInputs {
                epoch: 10,
                ..sealed_env(9)
            },
            tx(1),
        );
        assert_eq!(early.seal(0, 0), Err(SessionTrap::SealStanding(0)));

        // Lapsed: the seal will never open, so the round takes another
        // and the cell records the epoch running now.
        let mut lapsed = sealed_session(
            &set,
            EnvInputs {
                epoch: 8,
                ..sealed_env(9)
            },
            tx(1),
        );
        assert_eq!(lapsed.open_seal(0, 0), Ok(Drawn::Expired));
        assert_eq!(lapsed.seal(0, 0), Ok(()));
        assert_eq!(lapsed.cell_get(0, 0), Ok(8u64.to_le_bytes().to_vec()));
    }

    /// A seal is opened through the handle that holds it, so a
    /// capability that is not an exclusive write has no draw to give.
    #[test]
    fn a_seal_opens_only_through_the_cell_that_holds_it() {
        let set = declared(&[Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Read,
        }]);
        let mut session = session_under(MemoryStore::new(), &set, sealed_env(9));
        assert!(matches!(
            session.seal(0, 0),
            Err(SessionTrap::WrongMode {
                attempted: Op::Seal,
                ..
            })
        ));
        assert!(matches!(
            session.open_seal(0, 0),
            Err(SessionTrap::WrongMode {
                attempted: Op::OpenSeal,
                ..
            })
        ));
    }

    /// The two ways a seal fails to open are two answers, because a
    /// package does different things with them: wait, or close again.
    ///
    /// Both are reached by moving the window rather than the seal: what
    /// the cell records is fixed when it is written, so a seal is early
    /// or lapsed according to what the beacon has rolled since.
    #[test]
    fn an_early_seal_waits_where_a_lapsed_one_is_over() {
        let set = writing(key(1));
        let mut early = sealed_session(
            &set,
            EnvInputs {
                epoch: 10,
                ..sealed_env(9)
            },
            tx(1),
        );
        assert_eq!(early.open_seal(0, 0), Ok(Drawn::Pending));

        let mut lapsed = sealed_session(
            &set,
            EnvInputs {
                epoch: 8,
                ..sealed_env(9)
            },
            tx(1),
        );
        assert_eq!(lapsed.open_seal(0, 0), Ok(Drawn::Expired));
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

        let funds = session.reserve_take(0, 0).expect("the grant is held");
        assert_eq!(
            session.reserve_take(0, 0),
            Err(SessionTrap::ReservationTaken)
        );
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
