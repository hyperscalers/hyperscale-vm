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
//!
//! # The mode is a constant, so the dispatch is not one
//!
//! Every accessor below matches the handle's mode and refuses the rest.
//! At each generated call site the variant is fixed — an export's
//! prologue builds it from the resource type the parameter arrived as —
//! so the match has one live arm and the others are dead in every program
//! that links this crate. `#[inline(always)]` is what turns that from a
//! fact about the program into a fact about its code: the discriminant
//! folds at the call site and the refusing arms compile away.
//!
//! That is not an optimisation. A dead arm out of line is an
//! `unreachable` the deploy-time totality scan reads as a fault the body
//! can take, so it would deny the total mark to every method written in
//! this vocabulary for a branch none of them can execute.

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
    DeltaCell, Issuer, LockedCell, RangeRead, RangeWrite, ReadCell, ReserveCell, WriteCell,
};

use crate::Address;

/// The kernel's amount-cell width: a little-endian `u128`.
///
/// A stored amount is still bytes — a cell holds bytes — but one crossing
/// the boundary is an `amount`, so this width is the substate's rather
/// than the world's.
pub const AMOUNT_CELL_BYTES: usize = 16;

/// A `u128` as the kernel's world names it.
#[allow(clippy::cast_possible_truncation)] // taking a half is the truncation
fn amount(value: u128) -> kernel::state::Amount {
    kernel::state::Amount {
        low: value as u64,
        high: (value >> 64) as u64,
    }
}

/// The [`Address`] four world words name.
///
/// Called by generated code, which reads the fields at the call site: an
/// address reaches an export as the world's own record, and taking the
/// words rather than the record is what keeps that generated type out of
/// the SDK's signatures — a package's bindings and the SDK's are two
/// generations, and only one of them can own a name.
///
/// # Panics
///
/// On four words that do not name an address class. The kernel builds one
/// by evaluating the declaration, so a malformed one is a defect and the
/// trap is the deterministic answer to it.
#[must_use]
pub fn address_of(a: u64, b: u64, c: u64, d: u64) -> Address {
    let mut bytes = [0u8; 32];
    for (word, at) in [a, b, c, d].into_iter().zip(0..4) {
        bytes[at * 8..at * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    Address::from_bytes(bytes).expect("an address names a class")
}

/// The `u128` an `amount` carries.
const fn whole(value: kernel::state::Amount) -> u128 {
    (value.low as u128) | ((value.high as u128) << 64)
}

/// Split `value` off a bucket, as a bucket.
#[must_use]
pub fn bucket_take(funds: &kernel::state::Bucket, value: u128) -> kernel::state::Bucket {
    kernel::state::bucket_take(funds, amount(value))
}

/// Merge `other` into a bucket, consuming it.
pub fn bucket_put(funds: &kernel::state::Bucket, other: kernel::state::Bucket) {
    kernel::state::bucket_put(funds, other);
}

/// What a bucket carries, read through a borrow of the handle.
#[must_use]
pub fn bucket_amount(funds: &kernel::state::Bucket) -> u128 {
    whole(kernel::state::bucket_amount(funds))
}

/// Decode an amount cell. An absent cell reads as empty, which is zero.
#[must_use]
pub fn amount_of(cell: &[u8]) -> u128 {
    cell.try_into().map_or(0, u128::from_le_bytes)
}

/// Encode an amount into the kernel's cell representation.
#[must_use]
pub const fn amount_cell(amount: u128) -> [u8; AMOUNT_CELL_BYTES] {
    amount.to_le_bytes()
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
    issuer -> Issuer,
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
#[inline(always)]
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
#[inline(always)]
pub fn cell_set(handle: Handle, value: &[u8]) {
    match handle {
        Handle::Write(rep) => kernel::state::write_cell_set(&write_cell(rep), value),
        other => unreachable!("{other:?} does not write absolutes"),
    }
}

/// Move value into this handle's amount cell, consuming the bucket.
///
/// # Panics
///
/// On a handle whose mode moves no value.
#[inline(always)]
pub fn cell_put(handle: Handle, funds: kernel::state::Bucket) {
    match handle {
        Handle::Delta(rep) => kernel::state::delta_cell_put(&delta_cell(rep), funds),
        Handle::Write(rep) => kernel::state::write_cell_put(&write_cell(rep), funds),
        other => unreachable!("{other:?} carries no movement"),
    }
}

/// Move value out of this handle's amount cell.
///
/// # Panics
///
/// On a handle whose mode moves no value.
#[must_use]
#[inline(always)]
pub fn cell_take(handle: Handle, value: u128) -> kernel::state::Bucket {
    match handle {
        Handle::Delta(rep) => kernel::state::delta_cell_take(&delta_cell(rep), amount(value)),
        Handle::Write(rep) => kernel::state::write_cell_take(&write_cell(rep), amount(value)),
        other => unreachable!("{other:?} carries no movement"),
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
/// On any mode but [`Handle::Reserve`].
#[must_use]
#[inline(always)]
pub fn reserve_take(handle: Handle) -> kernel::state::Bucket {
    match handle {
        Handle::Reserve(rep) => kernel::state::reserve_cell_take(&reserve_cell(rep)),
        other => unreachable!("{other:?} holds no reservation"),
    }
}

/// Issue `value` of the resource this invocation was granted.
///
/// # Panics
///
/// Never from the guest's side: the grant is a handle the kernel lowered
/// against this method's own declared outputs, so a body holding one was
/// given one.
#[must_use]
#[inline(always)]
pub fn issue(rep: u32, value: u128) -> kernel::state::Bucket {
    kernel::state::issuer_take(&issuer(rep), amount(value))
}

/// Entries currently visible in this interval, bounded by its cap.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
#[inline(always)]
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
#[inline(always)]
pub fn entry_order(handle: Handle, index: u32) -> u128 {
    match handle {
        Handle::RangeRead(rep) => whole(kernel::state::range_read_order(&range_read(rep), index)),
        Handle::RangeWrite(rep) => {
            whole(kernel::state::range_write_order(&range_write(rep), index))
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
#[inline(always)]
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
#[inline(always)]
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
#[inline(always)]
pub fn entry_insert(handle: Handle, order: u128, value: &[u8]) {
    match handle {
        Handle::RangeWrite(rep) => {
            kernel::state::range_write_insert(&range_write(rep), amount(order), value);
        }
        other => unreachable!("{other:?} does not write entries"),
    }
}

/// Remove this interval's entry at `index`.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
#[inline(always)]
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
