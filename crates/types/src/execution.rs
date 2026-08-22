//! The record execution leaves behind: events and the outcome taxonomy.
//!
//! Both are receipt content — what a transaction *said* happened and how
//! it ended — carried on every participant of a cross-shard transaction
//! and checked byte for byte between committees. The caps here bound the
//! kernel's emission and the wire's decode with the same constants, so the
//! two cannot drift.

/// The rep an issuance grant is handed out under.
///
/// An invocation is granted issuance or it is not, so there is one, and
/// the constant is what says the number carries no information. Shared
/// because the kernel hands the grant out and the embedding lowers it.
pub const ISSUER_REP: u32 = 0;

/// The rep a handle occupies when the clause behind it was guarded out.
///
/// The capability table is indexed from zero, so the top of the range is
/// a position it never assigns. A guest is handed the handle all the
/// same, because an export's parameter list is a function of its
/// signature and cannot lose a parameter to a branch — what it is handed
/// is a handle that answers nothing, beside the flag saying so. Touching
/// one is a body whose control flow disagrees with the verdict it was
/// given, which is a defect and traps by its own name.
pub const ABSENT_REP: u32 = u32::MAX;

use hyperscale_hbor::Hbor;

use crate::address::{Address, EffectTarget, SubstateKey};
use crate::mode::Presence;

/// The events one transaction may emit.
///
/// A wire bound, not a price: event bytes are receipt content, priced by
/// the retention-byte rate like everything else a receipt retains. What
/// this bounds is the list a receipt decoder allocates.
pub const MAX_EVENTS_PER_TX: usize = 256;

/// The bytes one event payload may carry — a wire bound, on the same
/// terms as [`MAX_EVENTS_PER_TX`]: the bytes themselves are priced at
/// the retention rate, and this bounds what one decode allocates.
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 4096;

/// The bound on manifest nodes admission or routing will address.
///
/// A bound on pre-payment work: admission's single walk is linear in
/// the nodes and runs before any fee is assured, so what stands here is
/// a ceiling sized against the admission budget — the declared work the
/// walk produces is what carries a charge.
pub const MAX_MANIFEST_NODES: usize = 4096;

/// The bytes one node's answer may carry.
///
/// An answer is receipt payload whose size a guest chose, which is what
/// an event payload is — so it is bounded by that figure rather than by
/// one of its own.
pub const MAX_ANSWER_BYTES: usize = MAX_EVENT_PAYLOAD_BYTES;

/// The event types one package may declare — the bound on an emitted
/// index, checked without resolving it. A wire bound on the index.
pub const MAX_EVENT_TYPES: u32 = 1024;

/// The error codes one package may declare. A wire bound on the code.
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
    #[hbor(discriminant = 0)]
    Unreachable,
    /// Integer division or remainder by zero.
    #[hbor(discriminant = 1)]
    IntegerDivideByZero,
    /// `INT_MIN / -1` style overflow.
    #[hbor(discriminant = 2)]
    IntegerOverflow,
    /// Out-of-bounds linear memory access.
    #[hbor(discriminant = 3)]
    MemoryOutOfBounds,
    /// Out-of-bounds table access.
    #[hbor(discriminant = 4)]
    TableOutOfBounds,
    /// `call_indirect` through a null table entry.
    #[hbor(discriminant = 5)]
    IndirectCallToNull,
    /// `call_indirect` signature mismatch.
    #[hbor(discriminant = 6)]
    IndirectCallSignature,
    /// The call-depth bound: the blessed engine's stack limit, the
    /// interpreter's frame counter. Unreachable for an artifact the
    /// deploy-time frame bound admits.
    #[hbor(discriminant = 7)]
    StackExhausted,
    /// The transaction spent its signed ceiling.
    ///
    /// Charged as the declared limit rather than as the counter standing
    /// at the trap — that figure is engine-defined and no consensus
    /// reader may see it.
    #[hbor(discriminant = 8)]
    OutOfGas,
    /// A trap the profile does not model.
    ///
    /// The blessed engine's trap enum is open upstream and the profile
    /// validator admits a subset in which the rest cannot occur, so an
    /// occurrence is a defect in the profile rather than a guest's. The
    /// arm exists to keep the classification total without reopening a
    /// free-form one.
    #[hbor(discriminant = 9)]
    TrapOutsideProfile,
    /// A canonical-ABI violation: an unknown or wrongly typed handle,
    /// borrows still live at return, a call that would re-enter.
    ///
    /// One variant rather than four because the blessed engine surfaces
    /// most of these as an error that does not resolve to a trap kind. A
    /// finer vocabulary would be one the two runtimes could not populate
    /// identically, which is the divergence this type exists to exclude.
    #[hbor(discriminant = 10)]
    AbiViolation,
    /// A handle rep with no entry in the capability table.
    #[hbor(discriminant = 11)]
    HandleUnknown,
    /// A handle whose capability does not grant the operation.
    #[hbor(discriminant = 12)]
    HandleWrongMode,
    /// A handle whose clause was guarded out, reached anyway: a body
    /// whose control flow disagrees with the verdict it was handed.
    #[hbor(discriminant = 13)]
    UndeclaredBranch,
    /// A stored cell that is not a well-formed amount.
    ///
    /// A defect in state rather than in a call: amounts reach the kernel
    /// from a guest as a typed value, so the only way to meet one that is
    /// not an amount is to read a cell that was never written as one.
    #[hbor(discriminant = 14)]
    MalformedAmountCell,
    /// An entry index past the interval's current entries.
    #[hbor(discriminant = 15)]
    EntryIndexOutOfBounds,
    /// An insert whose order key falls outside the declared interval.
    #[hbor(discriminant = 16)]
    OrderOutsideInterval,
    /// More distinct entries written through one interval than the cap it
    /// declared.
    #[hbor(discriminant = 17)]
    IntervalWriteCapExceeded,
    /// A reservation the capability table promises but the store does not
    /// hold.
    #[hbor(discriminant = 18)]
    ReservationMissing,
    /// A second take of one reservation: the grant leaves the kernel
    /// once, so asking again is asking for value no hold covers.
    #[hbor(discriminant = 19)]
    ReservationAlreadyTaken,
    /// An issue by an invocation whose declaration granted it none.
    #[hbor(discriminant = 20)]
    IssuanceUngranted,
    /// A split past what a bucket holds.
    #[hbor(discriminant = 21)]
    BucketUnderflow,
    /// A merge whose total is past the width an amount has.
    #[hbor(discriminant = 22)]
    BucketOverflow,
    /// An operation reaching for the other kind of edge than the bucket
    /// carries.
    #[hbor(discriminant = 23)]
    WrongEdgeKind,
    /// One instance reaching two places at once.
    #[hbor(discriminant = 24)]
    InstanceHeldTwice,
    /// An instance a body named and the collection does not hold.
    #[hbor(discriminant = 25)]
    InstanceNotHeld,
    /// Value the transaction did not put down. A bucket is credited to a
    /// cell or handed back, and one still carrying anything when the
    /// transaction ends is the loss the linear model exists to exclude.
    ///
    /// Both ways of losing it, because they are one loss. A body that
    /// lets a handle go delivers the discard through the canonical ABI
    /// and the kernel refuses it there; a body that simply keeps one
    /// delivers nothing, and the kernel finds it holding value when the
    /// transaction closes.
    #[hbor(discriminant = 26)]
    ValueDropped,
    /// An emission outside any invocation, so the kernel has no address
    /// to stamp.
    #[hbor(discriminant = 27)]
    EmissionOutsideInvocation,
    /// An event type past the per-package ceiling.
    #[hbor(discriminant = 28)]
    EventTypeOutOfRange,
    /// A declined code past the per-package ceiling.
    #[hbor(discriminant = 29)]
    ErrorCodeOutOfRange,
    /// More events than one transaction may emit.
    #[hbor(discriminant = 30)]
    EventCountExceeded,
    /// An event payload past the per-event byte cap.
    #[hbor(discriminant = 31)]
    EventPayloadTooLarge,
    /// One judging batch carrying the same transaction and cell twice.
    #[hbor(discriminant = 33)]
    DuplicateReservationRequest,
    /// Held reservations exceeding the committed cell.
    #[hbor(discriminant = 34)]
    LedgerInvariant,
    /// Summing a fold's increments or decrements overflowed.
    #[hbor(discriminant = 35)]
    DeltaTotalOverflow,
    /// A fold that would push a cell above its maximum.
    #[hbor(discriminant = 36)]
    CellOverflow,
    /// A fold whose decrements exceed the cell's credited total.
    #[hbor(discriminant = 37)]
    CellUnderflow,
    /// A supply accumulator update past its bounds.
    #[hbor(discriminant = 38)]
    SupplyOutOfBounds,
    /// A wide operation asked to divide by zero, or handed a fraction
    /// with a zero denominator.
    ///
    /// Range-checked by the host regardless of what a guest's own types
    /// proved, because the ABI is not trusted.
    #[hbor(discriminant = 39)]
    MathDivideByZero,
    /// A wide result past 256 bits.
    #[hbor(discriminant = 40)]
    MathOverflow,
    /// A proportional split by a share above one, which would leave a
    /// negative remainder.
    #[hbor(discriminant = 41)]
    ShareAboveOne,
    /// Value moved into a cell denominated in some other resource, or
    /// merged into an edge carrying one.
    ///
    /// A package's declaration says what each cell it names holds; this
    /// is execution holding the code to it, so the property survives a
    /// metadata section nobody derived.
    #[hbor(discriminant = 42)]
    WrongResource,
    /// Value moved through a cell whose declaration denominates it in
    /// nothing, which would hand out an edge no destination could
    /// disagree with.
    #[hbor(discriminant = 43)]
    BytesAsValue,
    /// A commutative movement declared on a cell that denominates
    /// nothing. `Delta` and `Reserve` move value and do nothing else, so
    /// the cell they name is one whose contents the declaration owes an
    /// answer about.
    #[hbor(discriminant = 44)]
    UndenominatedMovement,
    /// Two clauses reaching one cell and disagreeing about what it
    /// holds, which would hand a body both the handle value moves
    /// through and the handle bytes are written to, over one leaf.
    #[hbor(discriminant = 45)]
    MixedContents,
    /// A declared mode and target combination the world cannot hand out.
    #[hbor(discriminant = 46)]
    EffectUnsupported,
    /// One transaction declaring an exclusive and a commutative mode on
    /// the same cell.
    #[hbor(discriminant = 49)]
    SelfConflictingModes,
    /// An already-held reservation whose amount differs from the declared
    /// one.
    #[hbor(discriminant = 50)]
    ReservationMismatch,
    /// A lowered call naming a capability past the materialized table.
    #[hbor(discriminant = 51)]
    CapabilityOutOfRange,
    /// A lowered call consuming an output edge no producer left.
    #[hbor(discriminant = 52)]
    MissingProducerEdge,
    /// A cell on a bounded edge that does not decode.
    #[hbor(discriminant = 53)]
    MalformedEdgeCell,
    /// An authority gate whose declared cell could not be read.
    #[hbor(discriminant = 54)]
    AuthorityCellUnreadable,
    /// An export whose returned blob does not split into the edges its
    /// signature declared.
    #[hbor(discriminant = 55)]
    BadReturnShape,
    /// A component that exports no function of the invoked name.
    #[hbor(discriminant = 56)]
    ExportMissing,
    /// The component would not instantiate.
    #[hbor(discriminant = 57)]
    InstantiationFailed,
    /// No compiled code for the called package.
    ///
    /// An embedder failing to resolve a package admission already
    /// accepted, so never the sender's defect and priced to nobody.
    #[hbor(discriminant = 58)]
    CodeUnavailable,
    /// A mint of the other kind than the grant's address commits: a
    /// fungible amount of a non-fungible resource, or the reverse.
    #[hbor(discriminant = 59)]
    WrongIssuanceKind,
    /// A produced non-fungible edge carrying ids other than the ones its
    /// declaration named.
    ///
    /// The declared ids are what admission keyed the instance cells by
    /// and what a consumer routed on, so an edge carrying any other set
    /// is a guest whose code and signature part company — the same
    /// standing a wrong-arity return has.
    #[hbor(discriminant = 60)]
    WrongMintedIds,
    /// An answer past [`MAX_ANSWER_BYTES`].
    ///
    /// A receipt carries what a method answered with, so the width one
    /// may carry is the vocabulary's rather than the guest's — the same
    /// standing an oversized event payload has, refused where the value
    /// comes back instead of at the encoding that could not hold it.
    #[hbor(discriminant = 61)]
    AnswerTooLarge,
    /// A cell opened as a seal that holds something else.
    ///
    /// A defect in a package rather than in a call: only the kernel
    /// writes a seal, so the bytes under one are its own — unless the
    /// package wrote over them through the same handle it opens with.
    #[hbor(discriminant = 62)]
    MalformedSeal,
}

/// What one node answered with: the value its method handed back, in the
/// encoding the method's own return type gives it.
///
/// Beside the edges rather than among them. An edge is value the kernel
/// takes ownership of and a later node can consume; an answer is bytes,
/// and the only thing that reads one is whoever reads the receipt.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Answer {
    /// The node whose call answered.
    pub node: u32,
    /// The value, as the method encoded it.
    #[hbor(max = MAX_ANSWER_BYTES)]
    pub value: Vec<u8>,
}

/// How execution ended: the abort taxonomy as the receipt records it.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum Outcome {
    /// The export returned, with whatever its nodes answered.
    #[hbor(discriminant = 0)]
    Completed {
        /// What each answering node handed back, in node order. Empty
        /// where no method the transaction called returns a value, and
        /// at most one per node, which is what bounds it.
        #[hbor(max = MAX_MANIFEST_NODES)]
        answers: Vec<Answer>,
    },
    /// A guest defect: a trap, a panic, a kernel refusal of bad guest
    /// arguments, a declaration defect. The sender's fault; priced at the
    /// sender.
    #[hbor(discriminant = 1)]
    UserError {
        /// The deterministic reason class.
        reason: AbortReason,
    },
    /// A lost deterministic race: a declared reservation the committed
    /// balance could not cover — aborted before any execution — or an
    /// unconditional debit past the floor of committed minus outstanding
    /// reservations, aborted at commit with its fuel charged.
    #[hbor(discriminant = 2)]
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
    #[hbor(discriminant = 3)]
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
    #[hbor(discriminant = 4)]
    Declined {
        /// The declining node.
        node: u32,
        /// The index into the declining package's error table.
        code: u32,
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
    #[hbor(discriminant = 7)]
    NullifierSpent {
        /// The nullifier cell an earlier committer wrote.
        key: SubstateKey,
    },
    /// A kernel or store invariant failure — never the sender's fault, and
    /// never expected to occur.
    #[hbor(discriminant = 8)]
    ProtocolError {
        /// The deterministic reason class.
        reason: AbortReason,
    },
    /// A declared condition the committed state or the presented
    /// evidence does not meet.
    ///
    /// Priced with [`Outcome::Infeasible`] rather than as a defect, for
    /// the reason the taxonomy gives [`Outcome::PresenceUnmet`] and
    /// [`Outcome::Unauthorized`]: a condition is a precondition on
    /// committed state, the world moved between signing and execution,
    /// and the protocol cannot tell an honest loser of that race from a
    /// careless caller.
    #[hbor(discriminant = 9)]
    ConditionUnmet {
        /// The condition that went unmet.
        condition: UnmetCondition,
    },
}

/// Which declared condition went unmet, shaped by where each kind is
/// judged.
///
/// A presence condition is judged where the leaf lives, against the
/// folded declaration, so it names its target; an authority condition is
/// judged at the calling node with that call's evidence, so it names the
/// node. The rule itself is not carried: the declaration is
/// content-addressed with the package, so the verdict points and the
/// metadata says what was asked.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum UnmetCondition {
    /// The leaf the condition names does not have the presence it
    /// requires.
    Holds {
        /// The target whose leaf did not meet it.
        target: EffectTarget,
        /// What the condition required of it. Never [`Presence::Either`],
        /// which requires nothing and so cannot go unmet.
        required: Presence,
    },
    /// The presented claims do not satisfy a rule the calling node's
    /// declaration requires.
    Satisfies {
        /// The calling node.
        node: u32,
    },
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{DecodeError, assert_canonical, from_slice, to_vec};

    use super::{
        AbortReason, Address, Answer, Event, MAX_EVENT_PAYLOAD_BYTES, Outcome, SubstateKey,
        UnmetCondition,
    };
    use crate::address::{AddressClass, EffectTarget, LocalKey};
    use crate::mode::Presence;

    /// Every abort class's wire byte, pinned one by one.
    ///
    /// The receipts a network commits carry these discriminants, so the
    /// pin is the upgrade discipline the type's doc promises: a mid-list
    /// insert that silently renamed every class after it fails here, and
    /// a new class joins by taking the next byte and a new line below.
    #[test]
    fn every_abort_class_keeps_its_wire_byte() {
        let classes = [
            (0, AbortReason::Unreachable),
            (1, AbortReason::IntegerDivideByZero),
            (2, AbortReason::IntegerOverflow),
            (3, AbortReason::MemoryOutOfBounds),
            (4, AbortReason::TableOutOfBounds),
            (5, AbortReason::IndirectCallToNull),
            (6, AbortReason::IndirectCallSignature),
            (7, AbortReason::StackExhausted),
            (8, AbortReason::OutOfGas),
            (9, AbortReason::TrapOutsideProfile),
            (10, AbortReason::AbiViolation),
            (11, AbortReason::HandleUnknown),
            (12, AbortReason::HandleWrongMode),
            (13, AbortReason::UndeclaredBranch),
            (14, AbortReason::MalformedAmountCell),
            (15, AbortReason::EntryIndexOutOfBounds),
            (16, AbortReason::OrderOutsideInterval),
            (17, AbortReason::IntervalWriteCapExceeded),
            (18, AbortReason::ReservationMissing),
            (19, AbortReason::ReservationAlreadyTaken),
            (20, AbortReason::IssuanceUngranted),
            (21, AbortReason::BucketUnderflow),
            (22, AbortReason::BucketOverflow),
            (23, AbortReason::WrongEdgeKind),
            (24, AbortReason::InstanceHeldTwice),
            (25, AbortReason::InstanceNotHeld),
            (26, AbortReason::ValueDropped),
            (27, AbortReason::EmissionOutsideInvocation),
            (28, AbortReason::EventTypeOutOfRange),
            (29, AbortReason::ErrorCodeOutOfRange),
            (30, AbortReason::EventCountExceeded),
            (31, AbortReason::EventPayloadTooLarge),
            (33, AbortReason::DuplicateReservationRequest),
            (34, AbortReason::LedgerInvariant),
            (35, AbortReason::DeltaTotalOverflow),
            (36, AbortReason::CellOverflow),
            (37, AbortReason::CellUnderflow),
            (38, AbortReason::SupplyOutOfBounds),
            (39, AbortReason::MathDivideByZero),
            (40, AbortReason::MathOverflow),
            (41, AbortReason::ShareAboveOne),
            (42, AbortReason::WrongResource),
            (43, AbortReason::BytesAsValue),
            (44, AbortReason::UndenominatedMovement),
            (45, AbortReason::MixedContents),
            (46, AbortReason::EffectUnsupported),
            (49, AbortReason::SelfConflictingModes),
            (50, AbortReason::ReservationMismatch),
            (51, AbortReason::CapabilityOutOfRange),
            (52, AbortReason::MissingProducerEdge),
            (53, AbortReason::MalformedEdgeCell),
            (54, AbortReason::AuthorityCellUnreadable),
            (55, AbortReason::BadReturnShape),
            (56, AbortReason::ExportMissing),
            (57, AbortReason::InstantiationFailed),
            (58, AbortReason::CodeUnavailable),
            (59, AbortReason::WrongIssuanceKind),
            (60, AbortReason::WrongMintedIds),
            (61, AbortReason::AnswerTooLarge),
            (62, AbortReason::MalformedSeal),
        ];
        for (byte, reason) in classes {
            assert_eq!(
                to_vec(&reason).expect("an abort class encodes"),
                vec![byte],
                "{reason:?} moved off wire byte {byte}",
            );
        }
    }

    /// Every outcome's wire discriminant, pinned with the same discipline.
    #[test]
    fn every_outcome_keeps_its_wire_discriminant() {
        let key = SubstateKey {
            owner: Address::new([2; 31], AddressClass::Component),
            local: LocalKey([3; 16]),
        };
        let outcomes = [
            (0, Outcome::Completed { answers: vec![] }),
            (
                1,
                Outcome::UserError {
                    reason: AbortReason::Unreachable,
                },
            ),
            (2, Outcome::Infeasible { key, amount: 0 }),
            (
                3,
                Outcome::ConstraintUnmet {
                    node: 0,
                    param: 0,
                    amount: 0,
                },
            ),
            (4, Outcome::Declined { node: 0, code: 0 }),
            (7, Outcome::NullifierSpent { key }),
            (
                8,
                Outcome::ProtocolError {
                    reason: AbortReason::Unreachable,
                },
            ),
            (
                9,
                Outcome::ConditionUnmet {
                    condition: UnmetCondition::Satisfies { node: 0 },
                },
            ),
        ];
        for (byte, outcome) in outcomes {
            assert_eq!(
                to_vec(&outcome).expect("an outcome encodes")[0],
                byte,
                "{outcome:?} moved off wire discriminant {byte}",
            );
        }
    }

    #[test]
    fn the_execution_record_is_canonical() {
        assert_canonical(&Event {
            emitter: Address::new([1; 31], AddressClass::Component),
            event_type: 3,
            payload: vec![9, 9],
        });
        assert_canonical(&Outcome::Completed {
            answers: vec![Answer {
                node: 1,
                value: vec![7],
            }],
        });
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
        assert_canonical(&Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(SubstateKey {
                    owner: Address::new([2; 31], AddressClass::Component),
                    local: LocalKey([3; 16]),
                }),
                required: Presence::Absent,
            },
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
