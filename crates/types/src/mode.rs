//! How a transaction declares it will reach a cell, and which pairs of
//! declarations may be in flight on one cell at the same time.
//!
//! Vocabulary rather than execution: the mode is chosen when a manifest
//! is written, travels with the routed declaration, and is read by
//! every layer that has to decide whether two transactions contend —
//! admission, the kernel's batch judge, and the shard's settlement
//! scheduler. It lives here because all three speak it and none of them
//! owns it.

use hyperscale_hbor::Hbor;

/// An access mode with its statically evaluated parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// Fresh coherent read of committed state.
    Read,
    /// Read of a locked substate: creation-fixed configuration, identical
    /// at every version.
    ///
    /// Immutability is what the mode buys and what it costs. Because no
    /// version of the target differs, the read needs no coherence and no
    /// proof: it carries no obligation, takes no admission key, and makes
    /// its owner no participant — the one mode a shard can serve without
    /// joining the transaction. And because it is verified by the target
    /// being locked rather than by attestation, it says nothing at all
    /// about mutable state; a read of that is [`Mode::Read`].
    Locked,
    /// Unconditional commutative increment or decrement; the amount is
    /// dynamic and never part of the declaration.
    Delta,
    /// Conditional decrement, feasible iff committed balance minus prior
    /// reservations covers the declared amount.
    Reserve {
        /// The statically evaluated amount feasibility is judged against.
        amount: u128,
    },
    /// Exclusive read-modify-write, feasible iff the leaf's presence is
    /// what the write requires of it.
    Write {
        /// What the leaf must be for the write to be feasible.
        requires: Presence,
    },
}

/// Which handle type a rep names — the mode lattice as the runtimes'
/// resource types.
///
/// Derived from the capability itself rather than declared beside it, so
/// an engine is told what to construct instead of inferring it from the
/// export it happens to be calling. Here rather than beside the engines
/// because two sides need it and neither is downstream of the other: an
/// engine constructing a handle, and routing naming the type of one it
/// is *not* going to construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellKind {
    /// `read-cell`.
    Read,
    /// `locked-cell`.
    Locked,
    /// `write-cell`: a cell holding bytes the package chose.
    Write,
    /// `amount-cell`: the same exclusive access to a cell holding value.
    ///
    /// Its own type rather than a `write-cell` the kernel refuses half of.
    /// Value moves through a bucket and bytes do not, so the two share no
    /// operation, and a package that named the wrong one is answered by
    /// the publish gate rather than by a trap at the call.
    Amount,
    /// `amount-read`: the same read of a cell holding value.
    ///
    /// Its own type for the reason [`CellKind::Amount`] is: a balance is
    /// a quantity and the cell holding it has no byte surface, so a read
    /// of one answers an amount and a read of the other answers bytes.
    /// One resource per question, rather than one that answers whichever
    /// the caller guessed.
    AmountRead,
    /// `delta-cell`.
    Delta,
    /// `reserve-cell`.
    Reserve,
    /// `range-read`.
    RangeRead,
    /// `range-write`: entries the package writes as bytes.
    RangeWrite,
    /// `instance-range`: the same interval over entries that are
    /// instances of one resource, on the terms [`CellKind::Amount`]
    /// states.
    InstanceRange,
}

impl CellKind {
    /// The world's name for this handle type.
    ///
    /// The WIT resource an engine constructs and an export borrows, so
    /// the publish gate holds a declared parameter to it and the macro
    /// renders it. One mapping, because a name that disagreed across the
    /// two would fail a package at publish for a reason neither side
    /// could name.
    #[must_use]
    pub const fn world_type(self) -> &'static str {
        match self {
            Self::Read => "read-cell",
            Self::Locked => "locked-cell",
            Self::Write => "write-cell",
            Self::Amount => "amount-cell",
            Self::AmountRead => "amount-read",
            Self::Delta => "delta-cell",
            Self::Reserve => "reserve-cell",
            Self::RangeRead => "range-read",
            Self::RangeWrite => "range-write",
            Self::InstanceRange => "instance-range",
        }
    }
}

/// What a write requires of the leaf it lands on.
///
/// Three places need "this write may only create" or "this write may
/// only update", and a body's `assert` answers none of them where it
/// matters: a declaration is what a caller routes on and what a wallet
/// reads, and a trap inside the body is invisible to both.
///
/// A parameter rather than a mode of its own, because **contention does
/// not change**: a create and a write on one cell exclude each other
/// exactly as two writes do. What changes is feasibility, which is the
/// same split [`Mode::Reserve`] already makes — its amount is a
/// feasibility parameter while [`ModeKind::Reserve`] is parameter-free
/// for scheduling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Presence {
    /// The leaf may or may not be there. What every declaration that
    /// says nothing means, which is why it is the default.
    #[default]
    Either,
    /// Feasible iff the leaf is absent — a first write, and a one-way
    /// door if nothing ever removes it.
    Absent,
    /// Feasible iff the leaf is there.
    Present,
}

impl Presence {
    /// What two requirements on one leaf mean together, or `None` where
    /// they mean nothing.
    ///
    /// Two writes on one cell are one write: `Either` concedes to a
    /// named requirement, and two opposite names concede to nothing.
    /// The lattice lives here alone because a declaration meets it
    /// twice — at publish over target expressions, and where the effect
    /// set is built over evaluated keys — and two copies would be two
    /// answers to one question.
    #[must_use]
    pub const fn meet(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Either, met) | (met, Self::Either) => Some(met),
            (Self::Absent, Self::Absent) => Some(Self::Absent),
            (Self::Present, Self::Present) => Some(Self::Present),
            (Self::Absent, Self::Present) | (Self::Present, Self::Absent) => None,
        }
    }
}

impl Mode {
    /// The mode's kind, for scheduling compatibility.
    #[must_use]
    pub const fn kind(&self) -> ModeKind {
        match self {
            Self::Read => ModeKind::Read,
            Self::Locked => ModeKind::Locked,
            Self::Delta => ModeKind::Delta,
            Self::Reserve { .. } => ModeKind::Reserve,
            Self::Write { .. } => ModeKind::Write,
        }
    }
}

/// Mode kinds, parameter-free, as scheduling compatibility consumes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModeKind {
    /// See [`Mode::Read`].
    Read,
    /// See [`Mode::Locked`].
    Locked,
    /// See [`Mode::Delta`].
    Delta,
    /// See [`Mode::Reserve`].
    Reserve,
    /// See [`Mode::Write { requires: Presence::Either }`].
    Write,
}

/// The scheduling compatibility relation: whether two in-flight
/// transactions may hold these modes on the same key concurrently.
///
/// A locked read is compatible with everything, and no longer by
/// assertion: its target is locked, and every mutating mode refuses a locked
/// target, so nothing can hold a conflicting mode on one. A fresh read
/// excludes every mutation; delta and reserve commute with each other;
/// write excludes everything but a locked read. Symmetric by construction.
#[must_use]
pub const fn compatible(a: ModeKind, b: ModeKind) -> bool {
    matches!(
        (a, b),
        (ModeKind::Locked, _)
            | (_, ModeKind::Locked)
            | (ModeKind::Read, ModeKind::Read)
            | (
                ModeKind::Delta | ModeKind::Reserve,
                ModeKind::Delta | ModeKind::Reserve
            )
    )
}

/// The three classes [`compatible`] partitions the conflicting modes
/// into: reads share with reads, the commutative modes with each other,
/// and a write shares with nothing.
///
/// Discriminants are stable indices, so a scheduler can key per-class
/// state by `class as usize`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictClass {
    /// Fresh reads: internally compatible.
    Read = 0,
    /// Delta and reserve: commute with each other.
    Commutative = 1,
    /// Exclusive writes: compatible with nothing that conflicts at all.
    Write = 2,
}

impl ConflictClass {
    /// Every class, ordered by discriminant.
    pub const ALL: [Self; 3] = [Self::Read, Self::Commutative, Self::Write];

    /// A mode kind standing for this class.
    ///
    /// The commutative modes are interchangeable under [`compatible`], so
    /// one of them speaks for both and conflict stays read off the
    /// lattice rather than tabulated again beside it.
    #[must_use]
    pub const fn representative(self) -> ModeKind {
        match self {
            Self::Read => ModeKind::Read,
            Self::Commutative => ModeKind::Delta,
            Self::Write => ModeKind::Write,
        }
    }

    /// Whether two classes conflict — [`compatible`], asked of the
    /// representatives.
    #[must_use]
    pub const fn conflicts_with(self, other: Self) -> bool {
        !compatible(self.representative(), other.representative())
    }
}

impl ModeKind {
    /// The conflict class this mode joins, or `None` for a locked read,
    /// which conflicts with nothing and joins no group.
    #[must_use]
    pub const fn conflict_class(self) -> Option<ConflictClass> {
        match self {
            Self::Locked => None,
            Self::Read => Some(ConflictClass::Read),
            Self::Delta | Self::Reserve => Some(ConflictClass::Commutative),
            Self::Write => Some(ConflictClass::Write),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ModeKind, Presence, compatible};

    /// The lattice both judges fold over: symmetric, idempotent, and
    /// with the indifferent requirement as its unit.
    #[test]
    fn presence_meets_symmetrically_around_the_indifferent_unit() {
        let all = [Presence::Either, Presence::Absent, Presence::Present];
        for left in all {
            assert_eq!(left.meet(left), Some(left), "idempotent");
            assert_eq!(left.meet(Presence::Either), Some(left), "unit");
            assert_eq!(Presence::Either.meet(left), Some(left), "unit");
            for right in all {
                assert_eq!(left.meet(right), right.meet(left), "symmetric");
            }
        }
        // The one pair with no answer.
        assert_eq!(Presence::Absent.meet(Presence::Present), None);
        assert_eq!(Presence::Present.meet(Presence::Absent), None);
    }
    #[test]
    fn compatibility_matrix() {
        use ModeKind::{Delta, Locked, Read, Reserve, Write};
        let kinds = [Read, Locked, Delta, Reserve, Write];
        let table = [
            [true, true, false, false, false],
            [true, true, true, true, true],
            [false, true, true, true, false],
            [false, true, true, true, false],
            [false, true, false, false, false],
        ];
        for (i, &a) in kinds.iter().enumerate() {
            for (j, &b) in kinds.iter().enumerate() {
                assert_eq!(compatible(a, b), table[i][j], "{a:?} vs {b:?}");
                assert_eq!(compatible(a, b), compatible(b, a), "symmetry {a:?}/{b:?}");
            }
        }
    }
}
