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
    /// Unconditional commutative increment or decrement; the amount is
    /// dynamic and never part of the declaration.
    Delta,
    /// Unconditional commutative increment, and no decrement.
    ///
    /// [`Delta`](Self::Delta) with one direction given up, which is what
    /// a method that only receives can say about itself. Two things turn
    /// on being able to say it. A credit cannot underflow, so it never
    /// fails feasibility — the only movement in the vocabulary that
    /// cannot. And a declaration that carries its direction can be judged
    /// on the movement it actually makes, where one that does not has to
    /// answer for both.
    ///
    /// Contends exactly as a delta does: giving up a direction gives up
    /// nothing a scheduler reads.
    Credit,
    /// Conditional decrement, feasible iff committed balance minus prior
    /// reservations covers the declared amount.
    Reserve {
        /// The statically evaluated amount feasibility is judged against.
        amount: u128,
    },
    /// Exclusive read-modify-write.
    ///
    /// What the leaf must be for the write to be feasible is not the
    /// mode's to say: a presence requirement is a condition the same
    /// declaration states, judged at materialization beside this.
    Write {
        /// Which directions value may move under it.
        ///
        /// The commutative modes say their direction by being
        /// themselves — a credit is a delta with one direction given up
        /// — and the exclusive one had no way to say it at all. So it
        /// says it here, and a collection, whose only movement mode this
        /// is, can say it too.
        moves: Moves,
    },
}

/// Which directions an access moves value in.
///
/// A parameter rather than a mode of its own, for the reason
/// [`Presence`] is one: **contention does not change**. An exclusive
/// hold excludes everything whichever way value moves under it, so
/// giving up a direction gives up nothing a scheduler reads — the same
/// trade [`Mode::Credit`] makes against [`Mode::Delta`].
///
/// What it changes is which of a resource's movement entries the access
/// earns. A declaration carrying its direction is judged on the movement
/// it actually makes; one that does not answers for both, which
/// over-binds — a holder permitted to send is asked for the receiving
/// credential too.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Moves {
    /// Value may arrive and may not leave.
    In,
    /// Value may leave and may not arrive.
    Out,
    /// Both, which is what an access saying nothing means.
    #[default]
    Both,
}

impl Moves {
    /// Whether value may arrive under it.
    #[must_use]
    pub const fn credits(self) -> bool {
        matches!(self, Self::In | Self::Both)
    }

    /// Whether value may leave under it.
    #[must_use]
    pub const fn debits(self) -> bool {
        matches!(self, Self::Out | Self::Both)
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
    /// Which directions value moves in under this mode, or `None` where
    /// it moves none.
    ///
    /// The one place the vocabulary's directions are read off, so a mode
    /// gaining an arm answers here or does not compile.
    #[must_use]
    pub const fn moves(&self) -> Option<Moves> {
        match self {
            Self::Read => None,
            Self::Delta => Some(Moves::Both),
            Self::Credit => Some(Moves::In),
            Self::Reserve { .. } => Some(Moves::Out),
            Self::Write { moves } => Some(*moves),
        }
    }

    /// The mode's kind, for scheduling compatibility.
    #[must_use]
    pub const fn kind(&self) -> ModeKind {
        match self {
            Self::Read => ModeKind::Read,
            Self::Delta => ModeKind::Delta,
            Self::Credit => ModeKind::Credit,
            Self::Reserve { .. } => ModeKind::Reserve,
            // The direction is a movement parameter and never a
            // scheduling one, exactly as a reservation's amount is.
            Self::Write { .. } => ModeKind::Write,
        }
    }
}

/// Mode kinds, parameter-free, as scheduling compatibility consumes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModeKind {
    /// See [`Mode::Read`].
    Read,
    /// See [`Mode::Delta`].
    Delta,
    /// See [`Mode::Credit`].
    Credit,
    /// See [`Mode::Reserve`].
    Reserve,
    /// See [`Mode::Write`].
    Write,
}

/// The scheduling compatibility relation: whether two in-flight
/// transactions may hold these modes on the same key concurrently.
///
/// A fresh read excludes every mutation; delta and reserve commute with
/// each other; write excludes everything, itself included. Symmetric by
/// construction.
#[must_use]
pub const fn compatible(a: ModeKind, b: ModeKind) -> bool {
    matches!(
        (a, b),
        (ModeKind::Read, ModeKind::Read)
            | (
                ModeKind::Delta | ModeKind::Credit | ModeKind::Reserve,
                ModeKind::Delta | ModeKind::Credit | ModeKind::Reserve
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
    /// The commutative movements: delta, credit and reserve.
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
    /// The conflict class this mode joins.
    #[must_use]
    pub const fn conflict_class(self) -> ConflictClass {
        match self {
            Self::Read => ConflictClass::Read,
            Self::Delta | Self::Credit | Self::Reserve => ConflictClass::Commutative,
            Self::Write => ConflictClass::Write,
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
        use ModeKind::{Delta, Read, Reserve, Write};
        let kinds = [Read, Delta, Reserve, Write];
        let table = [
            [true, false, false, false],
            [false, true, true, false],
            [false, true, true, false],
            [false, false, false, false],
        ];
        for (i, &a) in kinds.iter().enumerate() {
            for (j, &b) in kinds.iter().enumerate() {
                assert_eq!(compatible(a, b), table[i][j], "{a:?} vs {b:?}");
                assert_eq!(compatible(a, b), compatible(b, a), "symmetry {a:?}/{b:?}");
            }
        }
    }
}
