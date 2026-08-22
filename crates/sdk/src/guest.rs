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
use hyperscale_vm_types::{CellKind, Drawn, SEED_BYTES};
use kernel::state::{
    AmountCell, AmountCellRun, AmountRead, AmountReadRun, DeltaCell, DeltaCellRun, InstanceRange,
    InstanceRangeRun, Issuer, RangeRead, RangeReadRun, RangeWrite, RangeWriteRun, ReadCell,
    ReadCellRun, ReserveCell, ReserveCellRun, WriteCell, WriteCellRun,
};

use crate::Address;
pub use crate::handle::Handle;
use crate::num::{Rounding, Wide};

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

/// A wide word as the vocabulary holds it.
const fn lowered(value: kernel::math::Wide) -> Wide {
    Wide::from_limbs([value.limb0, value.limb1, value.limb2, value.limb3])
}

/// A wide word as the world's record.
const fn raised(value: Wide) -> kernel::math::Wide {
    let [limb0, limb1, limb2, limb3] = value.limbs();
    kernel::math::Wide {
        limb0,
        limb1,
        limb2,
        limb3,
    }
}

/// The rounding direction as the world's enum.
const fn direction(rounding: Rounding) -> kernel::math::Rounding {
    match rounding {
        Rounding::Down => kernel::math::Rounding::Down,
        Rounding::Up => kernel::math::Rounding::Up,
    }
}

/// `a * b / c`, the product held whole and rounded once.
#[must_use]
#[inline(always)]
pub fn mul_div(a: Wide, b: Wide, c: Wide, rounding: Rounding) -> Wide {
    lowered(kernel::math::mul_div(
        raised(a),
        raised(b),
        raised(c),
        direction(rounding),
    ))
}

/// `floor(sqrt(a * b))`, the product held whole.
#[must_use]
#[inline(always)]
pub fn geometric_mean(a: Wide, b: Wide) -> Wide {
    lowered(kernel::math::geometric_mean(raised(a), raised(b)))
}

/// `(an/ad) * (bn/bd)`, as a fraction in the same width.
#[must_use]
#[inline(always)]
pub fn fraction_compose(an: Wide, ad: Wide, bn: Wide, bd: Wide) -> (Wide, Wide) {
    let (num, den) = kernel::math::fraction_compose(raised(an), raised(ad), raised(bn), raised(bd));
    (lowered(num), lowered(den))
}

/// `base` raised to `exp` at the protocol's fixed scale, by squaring.
#[must_use]
#[inline(always)]
pub fn fixed_pow(base: Wide, exp: u32, rounding: Rounding) -> Wide {
    lowered(kernel::math::fixed_pow(
        raised(base),
        exp,
        direction(rounding),
    ))
}

/// `an/ad` against `bn/bd`, compared at a width their cross-products fit.
#[must_use]
#[inline(always)]
pub fn fraction_cmp(an: Wide, ad: Wide, bn: Wide, bd: Wide) -> core::cmp::Ordering {
    match kernel::math::fraction_cmp(raised(an), raised(ad), raised(bn), raised(bd)) {
        kernel::math::Ordering::Less => core::cmp::Ordering::Less,
        kernel::math::Ordering::Equal => core::cmp::Ordering::Equal,
        kernel::math::Ordering::Greater => core::cmp::Ordering::Greater,
    }
}

/// Split `value` off a bucket, as a bucket.
#[must_use]
pub fn bucket_take(funds: &kernel::state::Bucket, value: u128) -> kernel::state::Bucket {
    kernel::state::bucket_take(funds, amount(value))
}

/// Split `num/den` off a bucket, as a bucket.
#[must_use]
pub fn bucket_split(funds: &kernel::state::Bucket, num: Wide, den: Wide) -> kernel::state::Bucket {
    kernel::state::bucket_split(funds, raised(num), raised(den))
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
    write_cell -> WriteCell,
    amount_cell -> AmountCell,
    amount_read -> AmountRead,
    delta_cell -> DeltaCell,
    reserve_cell -> ReserveCell,
    range_read -> RangeRead,
    range_write -> RangeWrite,
    instance_range -> InstanceRange,
    read_cell_run -> ReadCellRun,
    write_cell_run -> WriteCellRun,
    amount_cell_run -> AmountCellRun,
    amount_read_run -> AmountReadRun,
    delta_cell_run -> DeltaCellRun,
    reserve_cell_run -> ReserveCellRun,
    range_read_run -> RangeReadRun,
    range_write_run -> RangeWriteRun,
    instance_range_run -> InstanceRangeRun,
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
        Handle::Write(rep) => kernel::state::write_cell_get(&write_cell(rep)),
        Handle::Run(CellKind::Read, rep, at) => {
            kernel::state::read_cell_run_get(&read_cell_run(rep), at)
        }
        Handle::Run(CellKind::Write, rep, at) => {
            kernel::state::write_cell_run_get(&write_cell_run(rep), at)
        }
        other => unreachable!("{other:?} reads no point substate"),
    }
}

/// What this handle's amount cell holds.
///
/// Beside [`cell_get`] rather than inside it: a cell holding value has
/// no byte surface, so the two answer different questions on different
/// handles and neither is the other's special case.
///
/// # Panics
///
/// On any mode but [`Handle::Amount`].
#[must_use]
#[inline(always)]
pub fn cell_balance(handle: Handle) -> u128 {
    match handle {
        Handle::Amount(rep) => whole(kernel::state::amount_cell_balance(&amount_cell(rep))),
        Handle::AmountRead(rep) => whole(kernel::state::amount_read_balance(&amount_read(rep))),
        Handle::Run(CellKind::Amount, rep, at) => whole(kernel::state::amount_cell_run_balance(
            &amount_cell_run(rep),
            at,
        )),
        Handle::Run(CellKind::AmountRead, rep, at) => whole(
            kernel::state::amount_read_run_balance(&amount_read_run(rep), at),
        ),
        other => unreachable!("{other:?} holds no balance"),
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
        Handle::Run(CellKind::Write, rep, at) => {
            kernel::state::write_cell_run_set(&write_cell_run(rep), at, value);
        }
        other => unreachable!("{other:?} does not write absolutes"),
    }
}

/// The world's `drawn`, as the vocabulary's own.
///
/// The limbs are the boundary's shape and the bytes are the word's, so
/// the conversion is here rather than in a body that would otherwise be
/// reassembling a width it was never told.
impl From<kernel::state::Drawn> for Drawn {
    fn from(drawn: kernel::state::Drawn) -> Self {
        match drawn {
            kernel::state::Drawn::Pending => Self::Pending,
            kernel::state::Drawn::Expired => Self::Expired,
            kernel::state::Drawn::Ready(word) => {
                let mut bytes = [0u8; SEED_BYTES];
                for (chunk, limb) in bytes
                    .chunks_exact_mut(8)
                    .zip([word.limb0, word.limb1, word.limb2, word.limb3])
                {
                    chunk.copy_from_slice(&limb.to_le_bytes());
                }
                Self::Ready(bytes)
            }
        }
    }
}

/// The draw the seal in this handle's cell matured into.
///
/// # Panics
///
/// On a handle that holds no exclusive write, which the declaration a
/// seal is read through rules out.
#[must_use]
pub fn cell_open_seal(handle: Handle, epoch: u64) -> Drawn {
    match handle {
        Handle::Write(rep) => kernel::state::write_cell_open_seal(&write_cell(rep), epoch).into(),
        other => unreachable!("{other:?} holds no seal"),
    }
}

/// End the substate this handle holds exclusively.
///
/// # Panics
///
/// On any mode but [`Handle::Write`].
#[inline(always)]
pub fn cell_clear(handle: Handle) {
    match handle {
        Handle::Write(rep) => kernel::state::write_cell_clear(&write_cell(rep)),
        Handle::Run(CellKind::Write, rep, at) => {
            kernel::state::write_cell_run_clear(&write_cell_run(rep), at);
        }
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
        Handle::Amount(rep) => kernel::state::amount_cell_put(&amount_cell(rep), funds),
        Handle::Run(CellKind::Delta, rep, at) => {
            kernel::state::delta_cell_run_put(&delta_cell_run(rep), at, funds);
        }
        Handle::Run(CellKind::Amount, rep, at) => {
            kernel::state::amount_cell_run_put(&amount_cell_run(rep), at, funds);
        }
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
        Handle::Amount(rep) => kernel::state::amount_cell_take(&amount_cell(rep), amount(value)),
        Handle::Run(CellKind::Delta, rep, at) => {
            kernel::state::delta_cell_run_take(&delta_cell_run(rep), at, amount(value))
        }
        Handle::Run(CellKind::Amount, rep, at) => {
            kernel::state::amount_cell_run_take(&amount_cell_run(rep), at, amount(value))
        }
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
        Handle::Run(CellKind::Reserve, rep, at) => {
            kernel::state::reserve_cell_run_take(&reserve_cell_run(rep), at)
        }
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
pub fn mint(rep: u32, value: u128) -> kernel::state::Bucket {
    kernel::state::mint(&issuer(rep), amount(value))
}

/// Create the named instances of what this invocation issues.
///
/// Never from the guest's side, on the terms [`mint`] states.
#[must_use]
#[inline(always)]
pub fn mint_instances(rep: u32, ids: &[u64]) -> kernel::state::Bucket {
    kernel::state::mint_instances(&issuer(rep), ids)
}

/// Destroy what a bucket carries, against this invocation's grant.
pub fn burn(rep: u32, funds: kernel::state::Bucket) {
    kernel::state::burn(&issuer(rep), funds);
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
        Handle::InstanceRange(rep) => kernel::state::instance_range_count(&instance_range(rep)),
        Handle::Run(CellKind::RangeRead, rep, at) => {
            kernel::state::range_read_run_count(&range_read_run(rep), at)
        }
        Handle::Run(CellKind::RangeWrite, rep, at) => {
            kernel::state::range_write_run_count(&range_write_run(rep), at)
        }
        Handle::Run(CellKind::InstanceRange, rep, at) => {
            kernel::state::instance_range_run_count(&instance_range_run(rep), at)
        }
        other => unreachable!("{other:?} is not an interval"),
    }
}

/// Whether this interval's page holds every entry the interval does.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
#[inline(always)]
pub fn entry_covered(handle: Handle) -> bool {
    match handle {
        Handle::RangeRead(rep) => kernel::state::range_read_covered(&range_read(rep)),
        Handle::RangeWrite(rep) => kernel::state::range_write_covered(&range_write(rep)),
        Handle::InstanceRange(rep) => kernel::state::instance_range_covered(&instance_range(rep)),
        Handle::Run(CellKind::RangeRead, rep, at) => {
            kernel::state::range_read_run_covered(&range_read_run(rep), at)
        }
        Handle::Run(CellKind::RangeWrite, rep, at) => {
            kernel::state::range_write_run_covered(&range_write_run(rep), at)
        }
        Handle::Run(CellKind::InstanceRange, rep, at) => {
            kernel::state::instance_range_run_covered(&instance_range_run(rep), at)
        }
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
        Handle::InstanceRange(rep) => whole(kernel::state::instance_range_order(
            &instance_range(rep),
            index,
        )),
        Handle::Run(CellKind::RangeRead, rep, at) => whole(kernel::state::range_read_run_order(
            &range_read_run(rep),
            at,
            index,
        )),
        Handle::Run(CellKind::RangeWrite, rep, at) => whole(kernel::state::range_write_run_order(
            &range_write_run(rep),
            at,
            index,
        )),
        Handle::Run(CellKind::InstanceRange, rep, at) => whole(
            kernel::state::instance_range_run_order(&instance_range_run(rep), at, index),
        ),
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
        Handle::InstanceRange(rep) => {
            kernel::state::instance_range_entry(&instance_range(rep), index)
        }
        Handle::Run(CellKind::RangeRead, rep, at) => {
            kernel::state::range_read_run_entry(&range_read_run(rep), at, index)
        }
        Handle::Run(CellKind::RangeWrite, rep, at) => {
            kernel::state::range_write_run_entry(&range_write_run(rep), at, index)
        }
        Handle::Run(CellKind::InstanceRange, rep, at) => {
            kernel::state::instance_range_run_entry(&instance_range_run(rep), at, index)
        }
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
        Handle::Run(CellKind::RangeWrite, rep, at) => {
            kernel::state::range_write_run_set(&range_write_run(rep), at, index, value);
        }
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
        Handle::Run(CellKind::RangeWrite, rep, at) => {
            kernel::state::range_write_run_insert(&range_write_run(rep), at, amount(order), value);
        }
        other => unreachable!("{other:?} does not write entries"),
    }
}

/// File the instances a bucket carries into this interval, each at the
/// order it was taken under, holding `value`.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
#[inline(always)]
pub fn entry_put(handle: Handle, funds: kernel::state::Bucket, value: &[u8]) {
    match handle {
        Handle::InstanceRange(rep) => {
            kernel::state::instance_range_put(&instance_range(rep), funds, value);
        }
        Handle::Run(CellKind::InstanceRange, rep, at) => {
            kernel::state::instance_range_run_put(&instance_range_run(rep), at, funds, value);
        }
        other => unreachable!("{other:?} carries no movement"),
    }
}

/// Take the instances `ids` names out of this interval.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
#[must_use]
#[inline(always)]
pub fn entry_take(handle: Handle, ids: &[u64]) -> kernel::state::Bucket {
    match handle {
        Handle::InstanceRange(rep) => kernel::state::instance_range_take(&instance_range(rep), ids),
        Handle::Run(CellKind::InstanceRange, rep, at) => {
            kernel::state::instance_range_run_take(&instance_range_run(rep), at, ids)
        }
        other => unreachable!("{other:?} carries no movement"),
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
        Handle::Run(CellKind::RangeWrite, rep, at) => {
            kernel::state::range_write_run_remove(&range_write_run(rep), at, index);
        }
        other => unreachable!("{other:?} does not write entries"),
    }
}

/// How many elements a run's site mapped over.
///
/// The element count rather than the count of expansions that fired, so
/// a body walks the same indices whichever of its sites it is reading —
/// and a site that did not fire reads as undeclared rather than
/// shortening the walk.
#[must_use]
#[inline(always)]
pub fn run_len(kind: CellKind, rep: u32) -> u32 {
    match kind {
        CellKind::Read => kernel::state::read_cell_run_len(&read_cell_run(rep)),
        CellKind::Write => kernel::state::write_cell_run_len(&write_cell_run(rep)),
        CellKind::Amount => kernel::state::amount_cell_run_len(&amount_cell_run(rep)),
        CellKind::AmountRead => kernel::state::amount_read_run_len(&amount_read_run(rep)),
        CellKind::Delta => kernel::state::delta_cell_run_len(&delta_cell_run(rep)),
        CellKind::Reserve => kernel::state::reserve_cell_run_len(&reserve_cell_run(rep)),
        CellKind::RangeRead => kernel::state::range_read_run_len(&range_read_run(rep)),
        CellKind::RangeWrite => kernel::state::range_write_run_len(&range_write_run(rep)),
        CellKind::InstanceRange => kernel::state::instance_range_run_len(&instance_range_run(rep)),
    }
}

/// Whether a run's site declared anything for the element at `index`.
#[must_use]
#[inline(always)]
pub fn run_declared(kind: CellKind, rep: u32, index: u32) -> bool {
    match kind {
        CellKind::Read => kernel::state::read_cell_run_declared(&read_cell_run(rep), index),
        CellKind::Write => kernel::state::write_cell_run_declared(&write_cell_run(rep), index),
        CellKind::Amount => kernel::state::amount_cell_run_declared(&amount_cell_run(rep), index),
        CellKind::AmountRead => {
            kernel::state::amount_read_run_declared(&amount_read_run(rep), index)
        }
        CellKind::Delta => kernel::state::delta_cell_run_declared(&delta_cell_run(rep), index),
        CellKind::Reserve => {
            kernel::state::reserve_cell_run_declared(&reserve_cell_run(rep), index)
        }
        CellKind::RangeRead => kernel::state::range_read_run_declared(&range_read_run(rep), index),
        CellKind::RangeWrite => {
            kernel::state::range_write_run_declared(&range_write_run(rep), index)
        }
        CellKind::InstanceRange => {
            kernel::state::instance_range_run_declared(&instance_range_run(rep), index)
        }
    }
}

/// The transaction clock, in milliseconds.
#[must_use]
pub fn clock_ms() -> u64 {
    kernel::env::clock()
}

/// The epoch this transaction executes in.
#[must_use]
pub fn epoch() -> u64 {
    kernel::env::epoch()
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
