//! The materialized handle a body's accessors call through.
//!
//! Carried on both targets, because both have something to call: a guest
//! build resolves it to the kernel import for its mode, and a host build
//! to the session behind the same operation. What it names is a position
//! in a table the kernel owns, which is why it is `(kind, rep)` and needs
//! nothing from either side to say so.

/// A materialized handle: the table index, and which of the kernel's
/// resource types it names.
///
/// The mode is not inferable from the accessor a body reaches for. A
/// leaf a method only reads arrives as a `read-cell`; the same leaf in a
/// method that also writes arrives as a `write-cell`, and `get` means
/// both. So the handle carries its own type, exactly as the kernel's
/// capability table does — passing a rep to the wrong resource is the
/// canonical ABI's mode-escape trap, which is the check working rather
/// than a check to avoid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handle {
    /// A declared fresh read.
    Read(u32),
    /// A read of a permanently locked substate.
    Locked(u32),
    /// A declared exclusive read-modify-write of a cell holding bytes.
    Write(u32),
    /// The same, of a cell holding value.
    Amount(u32),
    /// A read of a cell holding value.
    AmountRead(u32),
    /// A declared commutative movement on an amount cell.
    Delta(u32),
    /// A declared reservation, already judged and held.
    Reserve(u32),
    /// A declared read interval of an ordered collection.
    RangeRead(u32),
    /// A declared read-modify-write interval of entries the package
    /// writes as bytes.
    RangeWrite(u32),
    /// The same, of entries that are instances of one resource.
    InstanceRange(u32),
}
