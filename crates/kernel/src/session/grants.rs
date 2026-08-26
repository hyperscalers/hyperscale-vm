//! What a capability grants, decided in one place.
//!
//! Every operation the kernel exposes asks [`grants`] before it touches
//! the store, so the accept-set of a capability is one table read rather
//! than a match arm restated at each call. An operation added later cannot
//! forget to ask, because the capability it would act through is reached
//! only through the check.
//!
//! The table is total over both axes, which is what makes it testable.
//! An operation added to [`Op`] is an unhandled arm in [`grants`]; a
//! form added to [`Capability`] is one in [`describe`] and in
//! `Capability::form`, which is what puts it in front of the matrix
//! rather than leaving it a pairing nobody asked.

use super::materialize::Capability;

/// One operation a body performs through a handle.
///
/// Named for what the body does rather than for the world function that
/// carries it: two functions reaching the same store effect through
/// different modes are one operation asked of two capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Read a cell's bytes.
    Read,
    /// Replace a cell's bytes.
    Write,
    /// End the cell, so nothing is there.
    Clear,
    /// Commit the cell to the epoch now running.
    Seal,
    /// Resolve the draw the cell's seal matured into.
    OpenSeal,
    /// What an amount cell holds.
    Balance,
    /// Debit an amount cell.
    Take,
    /// Credit an amount cell.
    Put,
    /// What a reservation grants.
    ReservedAmount,
    /// Take the reservation as a bucket.
    TakeReserved,
    /// Read an interval's entries.
    ReadEntries,
    /// Write an interval's entries as bytes.
    WriteEntries,
    /// File instances into an interval.
    FileInstances,
    /// Take instances out of an interval.
    TakeInstances,
}

impl Op {
    /// Every operation, which is what makes the table testable in full:
    /// a matrix over this and [`Capability`] is the whole of what the
    /// kernel grants, and an operation added without a row in
    /// [`grants`] does not compile.
    pub const ALL: [Self; 14] = [
        Self::Read,
        Self::Write,
        Self::Clear,
        Self::Seal,
        Self::OpenSeal,
        Self::Balance,
        Self::Take,
        Self::Put,
        Self::ReservedAmount,
        Self::TakeReserved,
        Self::ReadEntries,
        Self::WriteEntries,
        Self::FileInstances,
        Self::TakeInstances,
    ];

    /// How a refusal names the operation, in the vocabulary a body's
    /// author used rather than the kernel's own method names.
    pub(super) const fn describe(self) -> &'static str {
        match self {
            Self::Read => "read the cell's bytes",
            Self::Write => "replace the cell's bytes",
            Self::Clear => "end the cell",
            Self::Seal => "seal the cell",
            Self::OpenSeal => "open the cell's seal",
            Self::Balance => "read the balance",
            Self::Take => "debit the cell",
            Self::Put => "credit the cell",
            Self::ReservedAmount => "read the reserved amount",
            Self::TakeReserved => "take the reservation",
            Self::ReadEntries => "read the interval's entries",
            Self::WriteEntries => "write the interval's entries",
            Self::FileInstances => "file instances into the interval",
            Self::TakeInstances => "take instances out of the interval",
        }
    }
}

/// Whether the capability held grants the operation attempted.
///
/// Read as a row per operation rather than per capability: what an
/// operation admits is the fact a reader needs, and stating it once is
/// what lets a form widen an accept-set without visiting every call site.
#[must_use]
pub const fn grants(held: &Capability, op: Op) -> bool {
    use Capability as C;
    match op {
        // Reading is what both byte modes answer: what the exclusive
        // mode adds is the writes, not a second answer to the same
        // question.
        Op::Read => matches!(held, C::Read(_) | C::Write(_)),
        Op::Write | Op::Clear | Op::Seal | Op::OpenSeal => matches!(held, C::Write(_)),
        // A read of a value cell is the one operation both value modes
        // answer: reading a balance moves none of it.
        Op::Balance => matches!(held, C::Amount { .. } | C::AmountRead(_)),
        // Both value modes move value; where they differ is when the
        // movement is judged, which the kernel reads off the capability.
        // A credit gave up the other direction, so it answers the credit
        // and not the debit — and the exclusive hold, which says its
        // direction in a field rather than by being itself, is read the
        // same way. Admission judged the access on the direction it
        // declared, so a movement the other way is one no entry was
        // asked about.
        Op::Take => match held {
            C::Amount { moves, .. } => moves.debits(),
            _ => matches!(held, C::Delta(_)),
        },
        Op::Put => match held {
            C::Amount { moves, .. } => moves.credits(),
            _ => matches!(held, C::Delta(_) | C::Credit(_)),
        },
        Op::ReservedAmount | Op::TakeReserved => matches!(held, C::Reserve { .. }),
        // Reading an interval is legal through every interval mode; the
        // narrower ones give up the writes, not the walk.
        Op::ReadEntries => {
            matches!(
                held,
                C::RangeRead(_) | C::RangeWrite(_) | C::Instances { .. }
            )
        }
        Op::WriteEntries => matches!(held, C::RangeWrite(_)),
        // The two directions of an interval, on the terms the two
        // directions of a value cell already have: an interval that gave
        // up a direction answers the movement it kept and not the other.
        Op::FileInstances => match held {
            C::Instances { moves, .. } => moves.credits(),
            _ => false,
        },
        Op::TakeInstances => match held {
            C::Instances { moves, .. } => moves.debits(),
            _ => false,
        },
    }
}
