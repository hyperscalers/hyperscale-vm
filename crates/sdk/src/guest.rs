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
//! The kernel lends one site per declared handle parameter and passes
//! them in the export's parameter order, so what a body holds is an
//! index into a table the kernel owns, and the element it names within
//! it. The accessors take that index and reconstruct
//! the borrow around it for the duration of one call — a handle a body
//! never owns and can never drop, which is what the canonical ABI's
//! `borrow` means and what keeps `state`'s types free of the lifetime a
//! stored borrow would put on every contract signature.
//!
//! # One accessor per world function, and nothing to choose between
//!
//! Every accessor below names its site and the element of it the access
//! covers, whether the declaration behind that site was one clause or a
//! loop's expansion. What the capability at that element grants is the
//! kernel's answer, held at the operation — so nothing here refuses, and
//! there is no arm a totality scan could read as a fault.

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
use hyperscale_vm_types::{Drawn, SEED_BYTES};
use kernel::state::Site;

use crate::Address;
pub use crate::handle::Handle;
use crate::num::{Rounding, Wide};
use crate::state::OrderKey;

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

/// The order key a world word names.
///
/// The kernel orders by the packed integer and knows nothing of what was
/// packed into it, so the type goes on here — at the seam, once, rather
/// than at each of the four sites a body reaches an interval through.
const fn ordered(value: kernel::state::Amount) -> OrderKey {
    OrderKey::from_bits(whole(value))
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
    site -> Site,
}

/// The substate this handle reads.
#[must_use]
#[inline(always)]
pub fn cell_get(handle: Handle) -> Vec<u8> {
    kernel::state::site_get(&site(handle.site), handle.element)
}

/// What this handle's amount cell holds.
///
/// Beside [`cell_get`] rather than inside it: a cell holding value has
/// no byte surface, so the two answer different questions and neither is
/// the other's special case.
#[must_use]
#[inline(always)]
pub fn cell_balance(handle: Handle) -> u128 {
    whole(kernel::state::site_balance(
        &site(handle.site),
        handle.element,
    ))
}

/// Replace the substate this handle holds exclusively.
#[inline(always)]
pub fn cell_set(handle: Handle, value: &[u8]) {
    kernel::state::site_set(&site(handle.site), handle.element, value)
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

/// Seal this handle's cell on the epoch now running.
#[inline(always)]
pub fn cell_seal(handle: Handle) {
    kernel::state::site_seal(&site(handle.site), handle.element)
}

/// The draw the seal in this handle's cell matures into.
#[must_use]
#[inline(always)]
pub fn cell_open_seal(handle: Handle) -> Drawn {
    kernel::state::site_open_seal(&site(handle.site), handle.element).into()
}

/// End this handle's cell, so nothing is there.
#[inline(always)]
pub fn cell_clear(handle: Handle) {
    kernel::state::site_clear(&site(handle.site), handle.element)
}

/// Credit this handle's amount cell with what the bucket carries.
#[inline(always)]
pub fn cell_put(handle: Handle, funds: kernel::state::Bucket) {
    kernel::state::site_put(&site(handle.site), handle.element, funds)
}

/// Debit this handle's amount cell, as a bucket.
#[must_use]
#[inline(always)]
pub fn cell_take(handle: Handle, value: u128) -> kernel::state::Bucket {
    kernel::state::site_take(&site(handle.site), handle.element, amount(value))
}

/// Take the reservation this method declared.
#[must_use]
#[inline(always)]
pub fn reserve_take(handle: Handle) -> kernel::state::Bucket {
    kernel::state::site_reserve_take(&site(handle.site), handle.element)
}

/// Create `value` of what the grant at `grant` names.
#[must_use]
#[inline(always)]
pub fn mint(grant: u32, value: u128) -> kernel::state::Bucket {
    kernel::state::mint(grant, amount(value))
}

/// Create the named instances of what the grant at `grant` names.
#[must_use]
#[inline(always)]
pub fn mint_instances(grant: u32, ids: &[u64]) -> kernel::state::Bucket {
    kernel::state::mint_instances(grant, ids)
}

/// Destroy value this invocation was granted, consuming the bucket.
#[inline(always)]
pub fn burn(funds: kernel::state::Bucket) {
    kernel::state::burn(funds);
}

/// Entries currently in this interval, bounded by its declared cap.
#[must_use]
#[inline(always)]
pub fn entry_count(handle: Handle) -> u32 {
    kernel::state::site_count(&site(handle.site), handle.element)
}

/// Whether this interval's page holds every entry the interval does.
#[must_use]
#[inline(always)]
pub fn entry_covered(handle: Handle) -> bool {
    kernel::state::site_covered(&site(handle.site), handle.element)
}

/// The order key of this interval's entry at `index`.
///
/// An exclusive interval reads its own keys: the write subsumes the
/// read, so walking one by order costs no second declaration.
#[must_use]
#[inline(always)]
pub fn entry_order(handle: Handle, index: u32) -> OrderKey {
    ordered(kernel::state::site_order(
        &site(handle.site),
        handle.element,
        index,
    ))
}

/// The value of this interval's entry at `index`.
#[must_use]
#[inline(always)]
pub fn entry_get(handle: Handle, index: u32) -> Vec<u8> {
    kernel::state::site_entry(&site(handle.site), handle.element, index)
}

/// The value of this interval's entry at `order`, or nothing if the
/// interval holds none.
#[must_use]
#[inline(always)]
pub fn entry_at(handle: Handle, order: OrderKey) -> Vec<u8> {
    (0..entry_count(handle))
        .find(|&index| entry_order(handle, index) == order)
        .map_or_else(Vec::new, |index| entry_get(handle, index))
}

/// Replace this interval's entry at `index`.
#[inline(always)]
pub fn entry_set(handle: Handle, index: u32, value: &[u8]) {
    kernel::state::site_entry_set(&site(handle.site), handle.element, index, value)
}

/// Insert (or replace) this interval's entry at `order`.
#[inline(always)]
pub fn entry_insert(handle: Handle, order: OrderKey, value: &[u8]) {
    kernel::state::site_insert(
        &site(handle.site),
        handle.element,
        amount(order.bits()),
        value,
    )
}

/// File every instance the bucket carries as an entry of this interval.
#[inline(always)]
pub fn entry_put(handle: Handle, funds: kernel::state::Bucket, value: &[u8]) {
    kernel::state::site_instance_put(&site(handle.site), handle.element, funds, value)
}

/// Take the named entries of this interval, as the instances they were.
#[must_use]
#[inline(always)]
pub fn entry_take(handle: Handle, ids: &[u64]) -> kernel::state::Bucket {
    kernel::state::site_instance_take(&site(handle.site), handle.element, ids)
}

/// Remove this interval's entry at `index`.
#[inline(always)]
pub fn entry_remove(handle: Handle, index: u32) {
    kernel::state::site_remove(&site(handle.site), handle.element, index)
}

/// How many elements the site covers.
///
/// The element count rather than the count of expansions that fired, so
/// a body walks the same indices whichever of its sites it is reading —
/// and a site that did not fire reads as undeclared rather than
/// shortening the walk.
#[must_use]
#[inline(always)]
pub fn site_len(rep: u32) -> u32 {
    kernel::state::site_len(&site(rep))
}

/// Whether the site declared anything for the element at `index`.
#[must_use]
#[inline(always)]
pub fn site_declared(rep: u32, index: u32) -> bool {
    kernel::state::site_declared(&site(rep), index)
}

/// The transaction clock, in milliseconds.
#[must_use]
pub fn clock_ms() -> u64 {
    kernel::env::clock()
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
