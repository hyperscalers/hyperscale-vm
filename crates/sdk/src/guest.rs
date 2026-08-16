//! The kernel imports a contract body executes against.
//!
//! [`state`](crate::state) is the Rust-facing shadow of
//! `hyperscale:kernel/state`; this is where the shadow meets the surface.
//! The WIT is vendored once here rather than beside each package, so the
//! world every contract compiles against is one file and a package that
//! drifted from it could not link.
//!
//! # Handles are reps, not borrows
//!
//! The kernel materializes one handle per declared clause and passes them
//! in the export's parameter order, so what a body holds is an index into
//! a table the kernel owns. The accessors take that index and reconstruct
//! the borrow around it for the duration of one call — a handle a body
//! never owns and can never drop, which is what the canonical ABI's
//! `borrow` means and what keeps `state`'s types free of the lifetime a
//! stored borrow would put on every contract signature.

// The kernel world, generated once for every package that links this
// crate. A guest names these types through its own world's `with`
// mapping, so its exports take the same Rust types the accessors below
// call the imports with — two generations of one interface would be two
// incompatible sets.
#[allow(missing_docs)] // the generated modules mirror the WIT's own docs
mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "kernel-imports",
        generate_all,
    });
}

use core::mem::ManuallyDrop;

pub use bindings::hyperscale::kernel;
use kernel::state::{
    DeltaCell, LockedCell, RangeRead, RangeWrite, ReadCell, ReserveCell, WriteCell,
};

/// The kernel's amount-cell width: a little-endian `u128`.
pub const AMOUNT_CELL_BYTES: usize = 16;

/// The amount a value edge carries, as it arrives at an export.
///
/// A bucket crosses the boundary as its amount and nothing else. The
/// resource is declared — the signature's outputs say what a produced
/// edge carries and the manifest's own edge says what a consumed one
/// does — so transmitting it would be a second, forgeable copy of a fact
/// the declaration already fixes.
#[must_use]
pub fn bucket_amount(cell: &[u8]) -> u128 {
    amount_of(cell)
}

/// The value edge an export returns, carrying `amount`.
#[must_use]
pub fn bucket_cell(amount: u128) -> Vec<u8> {
    amount_cell(amount)
}

/// Decode an amount cell. An absent cell reads as empty, which is zero.
#[must_use]
pub fn amount_of(cell: &[u8]) -> u128 {
    cell.try_into().map_or(0, u128::from_le_bytes)
}

/// Encode an amount into the kernel's cell representation.
#[must_use]
pub fn amount_cell(amount: u128) -> Vec<u8> {
    amount.to_le_bytes().to_vec()
}

/// Reconstruct one borrow per resource type, for the duration of a call.
///
/// The rep names a table entry the kernel owns and this body borrows.
/// [`ManuallyDrop`] is the whole of the discipline: the generated resource
/// type drops by calling the canonical ABI's `resource.drop`, which would
/// hand back a handle the body never owned.
macro_rules! borrows {
    ($($name:ident -> $ty:ident),* $(,)?) => {
        $(
            /// The borrow at `rep`, for the duration of one call.
            ///
            /// # Safety
            ///
            /// `rep` must name a live handle of this resource type — one
            /// the kernel materialized for this invocation and passed in.
            /// A rep from anywhere else is a handle the table does not
            /// hold, and the canonical ABI traps on it.
            fn $name(rep: u32) -> ManuallyDrop<$ty> {
                ManuallyDrop::new(unsafe { $ty::from_handle(rep) })
            }
        )*
    };
}

borrows! {
    read_cell -> ReadCell,
    locked_cell -> LockedCell,
    write_cell -> WriteCell,
    delta_cell -> DeltaCell,
    reserve_cell -> ReserveCell,
    range_read -> RangeRead,
    range_write -> RangeWrite,
}

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
    /// A declared exclusive read-modify-write.
    Write(u32),
    /// A declared commutative movement on an amount cell.
    Delta(u32),
    /// A declared reservation, already judged and held.
    Reserve(u32),
    /// A declared read interval of an ordered collection.
    RangeRead(u32),
    /// A declared read-modify-write interval.
    RangeWrite(u32),
}

/// The substate this handle reads.
///
/// # Panics
///
/// On a handle whose mode reads nothing point-shaped — an interval or a
/// reservation. Generated code never builds that call; a hand-written
/// body that does has declared one thing and reached for another.
#[must_use]
pub fn cell_get(handle: Handle) -> Vec<u8> {
    match handle {
        Handle::Read(rep) => kernel::state::read_cell_get(&read_cell(rep)),
        Handle::Locked(rep) => kernel::state::locked_cell_get(&locked_cell(rep)),
        Handle::Write(rep) => kernel::state::write_cell_get(&write_cell(rep)),
        other => unreachable!("{other:?} reads no point substate"),
    }
}

/// Replace the substate this handle holds exclusively.
///
/// # Panics
///
/// On any mode but [`Handle::Write`]: absolute outcomes are the
/// exclusive mode's alone.
pub fn cell_set(handle: Handle, value: &[u8]) {
    match handle {
        Handle::Write(rep) => kernel::state::write_cell_set(&write_cell(rep), value),
        other => unreachable!("{other:?} does not write absolutes"),
    }
}

/// A commutative credit on this handle's amount cell.
///
/// # Panics
///
/// On any mode but [`Handle::Delta`].
pub fn delta_add(handle: Handle, amount: u128) {
    match handle {
        Handle::Delta(rep) => {
            kernel::state::delta_cell_add(&delta_cell(rep), &amount_cell(amount));
        }
        other => unreachable!("{other:?} carries no movement"),
    }
}

/// A commutative debit on this handle's amount cell.
///
/// # Panics
///
/// On any mode but [`Handle::Delta`].
pub fn delta_sub(handle: Handle, amount: u128) {
    match handle {
        Handle::Delta(rep) => {
            kernel::state::delta_cell_sub(&delta_cell(rep), &amount_cell(amount));
        }
        other => unreachable!("{other:?} carries no movement"),
    }
}

/// The amount this reservation holds.
///
/// # Panics
///
/// On any mode but [`Handle::Reserve`].
#[must_use]
pub fn reserved(handle: Handle) -> u128 {
    match handle {
        Handle::Reserve(rep) => amount_of(&kernel::state::reserve_cell_amount(&reserve_cell(rep))),
        other => unreachable!("{other:?} holds no reservation"),
    }
}

/// The amount a declared reservation moved, checked against the amount
/// the declaration named.
///
/// Feasibility was judged before this body ran and the grant is what the
/// kernel already holds, so a reservation is read rather than performed.
/// What is left to establish is that the grant is the declared amount —
/// the one thing an executing body can still be surprised by, and a
/// deterministic trap when it is.
///
/// # Panics
///
/// On any mode but [`Handle::Reserve`], and on a grant that is not
/// `declared`.
#[must_use]
pub fn granted(handle: Handle, declared: u128) -> u128 {
    let held = reserved(handle);
    assert!(
        held == declared,
        "the reservation is not the amount declared"
    );
    held
}

/// Entries currently visible in this interval, bounded by its cap.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
pub fn entry_count(handle: Handle) -> u32 {
    match handle {
        Handle::RangeRead(rep) => kernel::state::range_read_count(&range_read(rep)),
        Handle::RangeWrite(rep) => kernel::state::range_write_count(&range_write(rep)),
        other => unreachable!("{other:?} is not an interval"),
    }
}

/// The order key of this interval's entry at `index`.
///
/// # Panics
///
/// On a handle that is not an interval. An exclusive interval reads its
/// own keys: the write subsumes the read, so walking one by order costs
/// no declaration the clause did not already make.
#[must_use]
pub fn entry_order(handle: Handle, index: u32) -> u128 {
    match handle {
        Handle::RangeRead(rep) => {
            amount_of(&kernel::state::range_read_order(&range_read(rep), index))
        }
        Handle::RangeWrite(rep) => {
            amount_of(&kernel::state::range_write_order(&range_write(rep), index))
        }
        other => unreachable!("{other:?} yields no order keys"),
    }
}

/// The value of this interval's entry at `index`.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
pub fn entry_get(handle: Handle, index: u32) -> Vec<u8> {
    match handle {
        Handle::RangeRead(rep) => kernel::state::range_read_entry(&range_read(rep), index),
        Handle::RangeWrite(rep) => kernel::state::range_write_entry(&range_write(rep), index),
        other => unreachable!("{other:?} yields no entries"),
    }
}

/// The value of the entry at `order`, or empty where there is none.
///
/// A collection's leaf has no key of its own — the kernel materializes an
/// interval covering it, and the order is what picks it out. Absent reads
/// as empty, on the same terms an absent substate does.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
pub fn entry_at(handle: Handle, order: u128) -> Vec<u8> {
    (0..entry_count(handle))
        .find(|&index| entry_order(handle, index) == order)
        .map_or_else(Vec::new, |index| entry_get(handle, index))
}

/// Replace this interval's entry at `index`.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
pub fn entry_set(handle: Handle, index: u32, value: &[u8]) {
    match handle {
        Handle::RangeWrite(rep) => kernel::state::range_write_set(&range_write(rep), index, value),
        other => unreachable!("{other:?} does not write entries"),
    }
}

/// Insert into this interval at `order`.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
pub fn entry_insert(handle: Handle, order: u128, value: &[u8]) {
    match handle {
        Handle::RangeWrite(rep) => {
            kernel::state::range_write_insert(&range_write(rep), &amount_cell(order), value);
        }
        other => unreachable!("{other:?} does not write entries"),
    }
}

/// Remove this interval's entry at `index`.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
pub fn entry_remove(handle: Handle, index: u32) {
    match handle {
        Handle::RangeWrite(rep) => kernel::state::range_write_remove(&range_write(rep), index),
        other => unreachable!("{other:?} does not write entries"),
    }
}

/// The transaction clock, in milliseconds.
#[must_use]
pub fn clock_ms() -> u64 {
    kernel::env::clock()
}

/// The transaction's randomness draw.
#[must_use]
pub fn randomness() -> Vec<u8> {
    kernel::env::randomness()
}

/// The protocol hash function.
#[must_use]
pub fn hash(data: &[u8]) -> Vec<u8> {
    kernel::crypto::hash(data)
}

/// Emit one event of the package's own type index.
pub fn emit(event_type: u32, payload: &[u8]) {
    kernel::events::emit(event_type, payload);
}
