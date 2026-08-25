//! The materialized handle a body's accessors call through.
//!
//! Carried on both targets, because both have something to call: a guest
//! build resolves it to the kernel import, and a host build to the
//! session behind the same operation. What it names is a position in a
//! table the kernel owns, and needs nothing from either side to say so.

/// A materialized handle: the table index it names, and whether the
/// table is the capability table or a run's own.
///
/// The mode is not here, because it is not the guest's to carry: what a
/// body may do through a handle is the capability's answer, held by the
/// kernel at every operation. What the guest must know is which table
/// its rep indexes, which is what the world's two resources say and what
/// this mirrors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handle {
    /// One declared access, at its position in the capability table.
    Capability(u32),
    /// One entry of a run over a `for-each` site's expansions: the run's
    /// own position, and the element the entry belongs to.
    Run(u32, u32),
}
