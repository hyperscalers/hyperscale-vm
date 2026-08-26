//! What a session refuses with, and the abort class each refusal is.
//!
//! Pure vocabulary: nothing here holds a session, reads a store or
//! decides anything. The mapping onto [`AbortReason`] is total, which is
//! what makes a refusal added here one the consensus taxonomy has to be
//! told about before it compiles.

use hyperscale_vm_types::math::MathError;
use hyperscale_vm_types::{
    AbortReason, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENTS_PER_TX, ResourceAddr, SubstateKey,
};

use super::{Capability, Op};
use crate::modes::ModeError;
use crate::store::StoreError;

/// A deterministic host refusal during execution: the same abort class on
/// every replica.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionTrap {
    /// A rep with no table entry — unreachable through either runtime's
    /// canonical ABI, kept as an honest error rather than a panic.
    #[error("unknown capability handle {0}")]
    UnknownHandle(u32),
    /// An element whose capability does not grant the operation.
    ///
    /// Carries both halves because the diagnostic is the whole value: a
    /// position alone says a body disagreed with its declaration without
    /// saying how, and this is the only signal a body reaching past its
    /// declaration gets. The capability rather than the mode it was
    /// materialized from: what a body may do is decided over the form
    /// the declaration produced, which folds the mode with what the
    /// target holds.
    #[error(
        "the handle at site {site} element {element} holds {}, which does not grant {}",
        held.described(),
        attempted.describe()
    )]
    Ungranted {
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
    /// what the leaf is for. The same refusal meets `seal` over such a
    /// cell: a seal cell is dedicated, and a first seal goes into a
    /// fresh one rather than over bytes a body still holds.
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
            SessionTrap::Ungranted { .. } => Self::HandleWrongMode,
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
