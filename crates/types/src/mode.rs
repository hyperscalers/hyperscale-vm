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
