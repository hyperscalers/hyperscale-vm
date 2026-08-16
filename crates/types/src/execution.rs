//! The record execution leaves behind: events and the outcome taxonomy.
//!
//! Both are receipt content — what a transaction *said* happened and how
//! it ended — carried on every participant of a cross-shard transaction
//! and checked byte for byte between committees. The caps here bound the
//! kernel's emission and the wire's decode with the same constants, so the
//! two cannot drift.

use hyperscale_hbor::Hbor;

use crate::address::{Address, SubstateKey};

/// The events one transaction may emit.
pub const MAX_EVENTS_PER_TX: usize = 256;

/// The bytes one event payload may carry.
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 4096;

/// The event types one package may declare — the bound on an emitted
/// index, checked without resolving it.
pub const MAX_EVENT_TYPES: u32 = 1024;

/// The error codes one package may declare.
///
/// The bound on a returned code, checked the same way an event index is
/// and for the same reason: the kernel is not holding the package's
/// metadata when the guest hands one back, so what it can enforce is the
/// ceiling rather than the table.
pub const MAX_ERROR_CODES: u32 = 1024;

/// One event a transaction emitted.
///
/// The kernel stamps the emitter from the invocation rather than taking it
/// from the guest — attribution is what decides which shard stores the
/// event, so it cannot be a claim. The type is an index into the emitting
/// package's event table; packages are content-addressed and immutable, so
/// an index can never come to mean something else, and resolving it is the
/// consumer's business.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Event {
    /// The instance that emitted it.
    pub emitter: Address,
    /// The index into the emitting package's event table.
    pub event_type: u32,
    /// The event's opaque payload.
    #[hbor(max = MAX_EVENT_PAYLOAD_BYTES)]
    pub payload: Vec<u8>,
}

/// Why a transaction aborted, as a class rather than as prose.
///
/// Closed and flat. Both runtimes classify their own refusals into it and
/// neither formats one, so the outcome a receipt records is the same
/// value on every replica and a differential lane can compare receipts
/// whole instead of erasing the reason first. The fee an abort carries is
/// a function of the [`Outcome`] variant, which makes the classification
/// consensus content and this the vocabulary that keeps it checkable.
///
/// Payload-free by construction: every abort with structure worth
/// carrying already has its own `Outcome` variant carrying it. What is
/// left here is a class, so nothing engine-derived can ride in. Which
/// handle, which index, which key is a diagnostic and goes to `tracing`.
///
/// The vocabulary is fixed by the protocol version and grows only by
/// upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum AbortReason {
    /// `unreachable` executed — what an `assert!` or a `panic!` becomes.
    Unreachable,
    /// Integer division or remainder by zero.
    IntegerDivideByZero,
    /// `INT_MIN / -1` style overflow.
    IntegerOverflow,
    /// Out-of-bounds linear memory access.
    MemoryOutOfBounds,
    /// Out-of-bounds table access.
    TableOutOfBounds,
    /// `call_indirect` through a null table entry.
    IndirectCallToNull,
    /// `call_indirect` signature mismatch.
    IndirectCallSignature,
    /// The call-depth bound: the blessed engine's stack limit, the
    /// interpreter's frame counter. Unreachable for an artifact the
    /// deploy-time frame bound admits.
    StackExhausted,
    /// The transaction spent its signed ceiling.
    ///
    /// Charged as the declared limit rather than as the counter standing
    /// at the trap — that figure is engine-defined and no consensus
    /// reader may see it.
    OutOfGas,
    /// A trap the profile does not model.
    ///
    /// The blessed engine's trap enum is open upstream and the profile
    /// validator admits a subset in which the rest cannot occur, so an
    /// occurrence is a defect in the profile rather than a guest's. The
    /// arm exists to keep the classification total without reopening a
    /// free-form one.
    TrapOutsideProfile,
    /// A canonical-ABI violation: an unknown or wrongly typed handle,
    /// borrows still live at return, a call that would re-enter.
    ///
    /// One variant rather than four because the blessed engine surfaces
    /// most of these as an error that does not resolve to a trap kind. A
    /// finer vocabulary would be one the two runtimes could not populate
    /// identically, which is the divergence this type exists to exclude.
    AbiViolation,
    /// A handle rep with no entry in the capability table.
    HandleUnknown,
    /// A handle whose capability does not grant the operation.
    HandleWrongMode,
    /// A value that is not a well-formed amount cell.
    MalformedAmountCell,
    /// A value that is not a well-formed order key.
    MalformedOrderCell,
    /// An entry index past the interval's current entries.
    EntryIndexOutOfBounds,
    /// An insert whose order key falls outside the declared interval.
    OrderOutsideInterval,
    /// More distinct entries written through one interval than the cap it
    /// declared.
    IntervalWriteCapExceeded,
    /// A reservation the capability table promises but the store does not
    /// hold.
    ReservationMissing,
    /// An emission outside any invocation, so the kernel has no address
    /// to stamp.
    EmissionOutsideInvocation,
    /// An event type past the per-package ceiling.
    EventTypeOutOfRange,
    /// A declined code past the per-package ceiling.
    ErrorCodeOutOfRange,
    /// More events than one transaction may emit.
    EventCountExceeded,
    /// An event payload past the per-event byte cap.
    EventPayloadTooLarge,
    /// A mutation of a permanently locked substate.
    SubstateLocked,
    /// One judging batch carrying the same transaction and cell twice.
    DuplicateReservationRequest,
    /// Held reservations exceeding the committed cell.
    LedgerInvariant,
    /// Summing a fold's increments or decrements overflowed.
    DeltaTotalOverflow,
    /// A fold that would push a cell above its maximum.
    CellOverflow,
    /// A fold whose decrements exceed the cell's credited total.
    CellUnderflow,
    /// A supply accumulator update past its bounds.
    SupplyOutOfBounds,
    /// A declared mode and target combination the world cannot hand out.
    EffectUnsupported,
    /// A mutation declared on a permanently locked substate.
    MutationOfLocked,
    /// A locked read declared on a substate that is not locked.
    LockedReadOfUnlocked,
    /// One transaction declaring an exclusive and a commutative mode on
    /// the same cell.
    SelfConflictingModes,
    /// An already-held reservation whose amount differs from the declared
    /// one.
    ReservationMismatch,
    /// A lowered call naming a capability past the materialized table.
    CapabilityOutOfRange,
    /// A lowered call consuming an output edge no producer left.
    MissingProducerEdge,
    /// A cell on a bounded edge that does not decode.
    MalformedEdgeCell,
    /// An authority gate whose declared cell could not be read.
    AuthorityCellUnreadable,
    /// An export whose returned blob does not split into the edges its
    /// signature declared.
    BadReturnShape,
    /// A component that exports no function of the invoked name.
    ExportMissing,
    /// The component would not instantiate.
    InstantiationFailed,
    /// No compiled code for the called package.
    ///
    /// An embedder failing to resolve a package admission already
    /// accepted, so never the sender's defect and priced to nobody.
    CodeUnavailable,
}

/// How execution ended: the abort taxonomy as the receipt records it.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum Outcome {
    /// The export returned; its scalar result if it had one.
    Completed {
        /// The export's return value, when the signature has one.
        value: Option<u64>,
    },
    /// A guest defect: a trap, a panic, a kernel refusal of bad guest
    /// arguments, a declaration defect. The sender's fault; priced at the
    /// sender.
    UserError {
        /// The deterministic reason class.
        reason: AbortReason,
    },
    /// A lost deterministic race: a declared reservation the committed
    /// balance could not cover — aborted before any execution — or an
    /// unconditional debit past the floor of committed minus outstanding
    /// reservations, aborted at commit with its fuel charged.
    Infeasible {
        /// The cell that could not cover it.
        key: SubstateKey,
        /// The uncovered amount.
        amount: u128,
    },
    /// A signed edge bound the produced amount did not meet.
    ///
    /// The manifest's own guarantee, asserted independently of the callee:
    /// a producer returning less than the consumer declared fails the
    /// transaction whatever the producer's own code checked. Priced with
    /// [`Outcome::Infeasible`] rather than as a defect — the sender
    /// declared a bound and the world moved between signing and
    /// execution, which is a lost race.
    ConstraintUnmet {
        /// The consuming node.
        node: u32,
        /// The consumed parameter's position on that node.
        param: u32,
        /// What the edge actually carried.
        amount: u128,
    },
    /// A method declined on its own terms: it returned on its error arm
    /// rather than trapping.
    ///
    /// A declared refusal rather than a defect, and priced as one. The
    /// export *returned*, so its fuel is an ordinary completed-invocation
    /// figure — agreed between the runtimes by construction, unlike the
    /// counter standing at a trap — which is what makes this the abort
    /// class a refundable execution charge can settle against once
    /// host-side fee settlement lands. Until then it pays the floor, the
    /// same class a lost race pays.
    Declined {
        /// The declining node.
        node: u32,
        /// The index into the declining package's error table.
        code: u32,
    },
    /// A guarded call whose presented evidence does not satisfy its
    /// target's gate.
    ///
    /// Priced with [`Outcome::Infeasible`] rather than as a defect: a
    /// stored rule can change between signing and execution, so
    /// presented authority a target no longer admits is a stale
    /// declaration — the class a spent nullifier occupies for the same
    /// reason. Whether the gate still admits the presentation is the
    /// target's state, which is why the verdict is reached here rather
    /// than at admission.
    Unauthorized {
        /// The calling node.
        node: u32,
    },
    /// A subintent this transaction commits was already spent.
    ///
    /// The composer lost a race it could not have won: canonical order
    /// picks between two compositions carrying one subintent, an earlier
    /// block may have committed it, or its signer may have cancelled it
    /// by spending the nullifier directly. None of those is visible to a
    /// composer at signing time, so this is priced with
    /// [`Outcome::Infeasible`] — a conflict tiebreak and a stale
    /// declaration are the two cases the taxonomy names.
    NullifierSpent {
        /// The nullifier cell an earlier committer wrote.
        key: SubstateKey,
    },
    /// A kernel or store invariant failure — never the sender's fault, and
    /// never expected to occur.
    ProtocolError {
        /// The deterministic reason class.
        reason: AbortReason,
    },
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{DecodeError, assert_canonical, from_slice, to_vec};

    use super::{AbortReason, Address, Event, MAX_EVENT_PAYLOAD_BYTES, Outcome, SubstateKey};
    use crate::address::{AddressClass, LocalKey};

    #[test]
    fn the_execution_record_is_canonical() {
        assert_canonical(&Event {
            emitter: Address::new([1; 31], AddressClass::Component),
            event_type: 3,
            payload: vec![9, 9],
        });
        assert_canonical(&Outcome::Completed { value: Some(7) });
        assert_canonical(&Outcome::Infeasible {
            key: SubstateKey {
                owner: Address::new([2; 31], AddressClass::Component),
                local: LocalKey([3; 16]),
            },
            amount: 100,
        });
        assert_canonical(&Outcome::UserError {
            reason: AbortReason::Unreachable,
        });
    }

    /// A peer's claim, built without the cap the emitter enforces.
    #[derive(Debug, Clone, PartialEq, Eq, hyperscale_hbor::Hbor)]
    struct Uncapped {
        emitter: Address,
        event_type: u32,
        payload: Vec<u8>,
    }

    /// The wire refuses what the kernel would never emit, on the same
    /// constant the kernel enforces.
    #[test]
    fn an_oversized_payload_rejects_at_decode() {
        let mut over = Event {
            emitter: Address::new([1; 31], AddressClass::Component),
            event_type: 0,
            payload: vec![0; MAX_EVENT_PAYLOAD_BYTES + 1],
        };
        assert!(to_vec(&over).is_err());
        over.payload.truncate(MAX_EVENT_PAYLOAD_BYTES);
        let bytes = to_vec(&over).unwrap();
        assert!(from_slice::<Event>(&bytes).is_ok());

        let smuggled = to_vec(&Uncapped {
            emitter: Address::new([1; 31], AddressClass::Component),
            event_type: 0,
            payload: vec![0; MAX_EVENT_PAYLOAD_BYTES + 1],
        })
        .unwrap();
        assert!(matches!(
            from_slice::<Event>(&smuggled),
            Err(DecodeError::BoundExceeded { .. })
        ));
    }
}
