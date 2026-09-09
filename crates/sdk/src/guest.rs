//! The kernel imports a contract body executes against.
//!
//! [`state`](crate::state) is the Rust-facing shadow of
//! `hyperscale:kernel/state`; this is where the shadow meets the
//! boundary. The imports are declared here once, at the core types the
//! kernel defines them at, so a package that drifted from the boundary
//! could not link.
//!
//! # Handles are reps
//!
//! The kernel lends one site per declared handle parameter and passes
//! them in the export's parameter order, so what a body holds is an
//! index into a table the kernel owns, and the element it names within
//! it. A bucket is the same index for value in flight, wrapped in
//! [`BucketHandle`] so a body that lets one go tells the kernel so.
//!
//! # Bytes cross through registers
//!
//! A variable-length result waits in the kernel's answer register until
//! the body has made room for it: the import returns the length, the
//! accessor allocates, and [`take`] collects the bytes. An export's
//! non-scalar arguments wait in input registers the same way, and the
//! generated prologue collects them with [`arg`]. What an export hands
//! back goes the other way through [`reply`] and [`answer`].
//!
//! # One accessor per import, and nothing to choose between
//!
//! Every accessor below names its site and the element of it the access
//! covers, whether the declaration behind that site was one clause or a
//! loop's expansion. What the capability at that element grants is the
//! kernel's answer, held at the operation — so nothing here refuses, and
//! there is no arm a totality scan could read as a fault.

use hyperscale_vm_types::{Drawn, SEED_BYTES};

use crate::Address;
pub use crate::handle::Handle;
use crate::num::{Rounding, Wide};
use crate::state::OrderKey;

#[link(wasm_import_module = "hyperscale:kernel/abi")]
unsafe extern "C" {
    #[link_name = "arg"]
    fn abi_arg(index: u32, ptr: u32);
    #[link_name = "take"]
    fn abi_take(ptr: u32);
    #[link_name = "reply"]
    fn abi_reply(ptr: u32, count: u32);
    #[link_name = "answer"]
    fn abi_answer(ptr: u32, len: u32);
}

#[link(wasm_import_module = "hyperscale:kernel/state")]
unsafe extern "C" {
    #[link_name = "site-len"]
    fn state_site_len(site: u32) -> u32;
    #[link_name = "site-declared"]
    fn state_site_declared(site: u32, element: u32) -> u32;
    #[link_name = "site-get"]
    fn state_site_get(site: u32, element: u32) -> u32;
    #[link_name = "site-set"]
    fn state_site_set(site: u32, element: u32, ptr: u32, len: u32);
    #[link_name = "site-seal"]
    fn state_site_seal(site: u32, element: u32);
    #[link_name = "site-open-seal"]
    fn state_site_open_seal(site: u32, element: u32, out: u32) -> u32;
    #[link_name = "site-clear"]
    fn state_site_clear(site: u32, element: u32);
    #[link_name = "site-balance"]
    fn state_site_balance(site: u32, element: u32, out: u32);
    #[link_name = "site-take"]
    fn state_site_take(site: u32, element: u32, amount: u32) -> u32;
    #[link_name = "site-put"]
    fn state_site_put(site: u32, element: u32, funds: u32);
    #[link_name = "site-reserve-take"]
    fn state_site_reserve_take(site: u32, element: u32) -> u32;
    #[link_name = "site-count"]
    fn state_site_count(site: u32, element: u32) -> u32;
    #[link_name = "site-covered"]
    fn state_site_covered(site: u32, element: u32) -> u32;
    #[link_name = "site-order"]
    fn state_site_order(site: u32, element: u32, index: u32, out: u32);
    #[link_name = "site-entry"]
    fn state_site_entry(site: u32, element: u32, index: u32) -> u32;
    #[link_name = "site-entry-set"]
    fn state_site_entry_set(site: u32, element: u32, index: u32, ptr: u32, len: u32);
    #[link_name = "site-insert"]
    fn state_site_insert(site: u32, element: u32, order: u32, ptr: u32, len: u32);
    #[link_name = "site-remove"]
    fn state_site_remove(site: u32, element: u32, index: u32);
    #[link_name = "site-instance-take"]
    fn state_site_instance_take(site: u32, element: u32, ids: u32, count: u32) -> u32;
    #[link_name = "site-instance-put"]
    fn state_site_instance_put(site: u32, element: u32, funds: u32, ptr: u32, len: u32);
    #[link_name = "bucket-take"]
    fn state_bucket_take(bucket: u32, amount: u32) -> u32;
    #[link_name = "bucket-split"]
    fn state_bucket_split(bucket: u32, num: u32, den: u32) -> u32;
    #[link_name = "bucket-put"]
    fn state_bucket_put(bucket: u32, other: u32);
    #[link_name = "bucket-amount"]
    fn state_bucket_amount(bucket: u32, out: u32);
    #[link_name = "bucket-drop"]
    fn state_bucket_drop(bucket: u32);
    #[link_name = "mint"]
    fn state_mint(grant: u32, amount: u32) -> u32;
    #[link_name = "mint-instances"]
    fn state_mint_instances(grant: u32, ids: u32, count: u32) -> u32;
    #[link_name = "burn"]
    fn state_burn(funds: u32);
}

#[link(wasm_import_module = "hyperscale:kernel/math")]
unsafe extern "C" {
    #[link_name = "mul-div"]
    fn math_mul_div(a: u32, b: u32, c: u32, r: u32, out: u32);
    #[link_name = "geometric-mean"]
    fn math_geometric_mean(a: u32, b: u32, out: u32);
    #[link_name = "fraction-compose"]
    fn math_fraction_compose(an: u32, ad: u32, bn: u32, bd: u32, out_num: u32, out_den: u32);
    #[link_name = "fraction-cmp"]
    fn math_fraction_cmp(an: u32, ad: u32, bn: u32, bd: u32) -> u32;
    #[link_name = "fixed-pow"]
    fn math_fixed_pow(base: u32, exp: u32, r: u32, out: u32);
}

#[link(wasm_import_module = "hyperscale:kernel/env")]
unsafe extern "C" {
    #[link_name = "clock"]
    fn env_clock() -> u64;
}

#[link(wasm_import_module = "hyperscale:kernel/crypto")]
unsafe extern "C" {
    #[link_name = "hash"]
    fn crypto_hash(ptr: u32, len: u32, out: u32);
}

#[link(wasm_import_module = "hyperscale:kernel/events")]
unsafe extern "C" {
    #[link_name = "emit"]
    fn events_emit(event_type: u32, ptr: u32, len: u32);
}

/// A pointer as the boundary carries it.
#[allow(clippy::cast_possible_truncation)] // a wasm32 pointer is 32 bits
fn ptr<T>(at: *const T) -> u32 {
    at as usize as u32
}

/// A pointer the kernel writes through, as the boundary carries it.
#[allow(clippy::cast_possible_truncation)] // a wasm32 pointer is 32 bits
fn room<T>(at: *mut T) -> u32 {
    at as usize as u32
}

/// A length as the boundary carries it.
#[allow(clippy::cast_possible_truncation)] // a wasm32 length is 32 bits
const fn len(bytes: &[u8]) -> u32 {
    bytes.len() as u32
}

/// A count as the boundary carries it.
#[allow(clippy::cast_possible_truncation)] // a wasm32 count is 32 bits
const fn count<T>(items: &[T]) -> u32 {
    items.len() as u32
}

/// Collects the answer register: `len` bytes the last import left there.
///
/// Never inlined, and neither collector below is: making room for a
/// register is the boundary's work, and the totality scan sets a
/// collector aside as the boundary's support — which it can only do
/// while the collect is a function of its own.
#[inline(never)]
fn take(len: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; len as usize];
    // SAFETY: the register holds exactly `len` bytes, and the vector has
    // room for them.
    unsafe { abi_take(room(bytes.as_mut_ptr())) };
    bytes
}

/// Collects input register `index`: `len` bytes of one export argument.
///
/// Called by generated prologues, once per non-scalar parameter.
#[must_use]
#[inline(never)]
pub fn arg(index: u32, len: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; len as usize];
    // SAFETY: the register holds exactly `len` bytes, and the vector has
    // room for them.
    unsafe { abi_arg(index, room(bytes.as_mut_ptr())) };
    bytes
}

/// Hands the kernel the edges an export produced, in declared output
/// order. Called by generated epilogues, exactly once per completed
/// call.
pub fn reply(edges: &[u32]) {
    // SAFETY: the slice is `count` little-endian `u32`s at `ptr`.
    unsafe { abi_reply(ptr(edges.as_ptr()), count(edges)) };
}

/// Hands the kernel the bytes an export answers with. Called by
/// generated epilogues, once, where the method answers.
pub fn answer(bytes: &[u8]) {
    // SAFETY: the slice is `len` bytes at `ptr`.
    unsafe { abi_answer(ptr(bytes.as_ptr()), len(bytes)) };
}

/// The handle the kernel holds a bucket behind.
///
/// A body holds the index and the kernel holds the value; letting the
/// handle go tells the kernel so, which is what keeps a discarded
/// bucket from being a bucket nobody can reach. Consuming it hands the
/// index to an import that takes the bucket, and no drop follows.
#[derive(Debug, PartialEq, Eq)]
pub struct BucketHandle(u32);

impl BucketHandle {
    /// The bucket the kernel holds at `rep`.
    ///
    /// Called by generated code, never by an author: the only ways to
    /// hold value are to be handed some, to take some from a cell the
    /// method declared, and to mint some, and none of them is a
    /// constructor a body can reach.
    #[must_use]
    pub const fn from_rep(rep: u32) -> Self {
        Self(rep)
    }

    /// The index the kernel holds this bucket at.
    #[must_use]
    pub const fn rep(&self) -> u32 {
        self.0
    }

    /// The index, and no drop: the import this feeds takes the bucket.
    #[must_use]
    pub const fn into_rep(self) -> u32 {
        let rep = self.0;
        core::mem::forget(self);
        rep
    }
}

impl Drop for BucketHandle {
    fn drop(&mut self) {
        // SAFETY: a plain scalar call.
        unsafe { state_bucket_drop(self.0) };
    }
}

/// An amount as the boundary carries it: sixteen little-endian bytes.
const fn amount(value: u128) -> [u8; 16] {
    value.to_le_bytes()
}

/// A wide as the boundary carries it: four little-endian limbs.
fn raised(value: Wide) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(value.limbs()) {
        *chunk = limb.to_le_bytes();
    }
    bytes
}

/// The wide four little-endian limbs name.
fn lowered(bytes: &[u8; 32]) -> Wide {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*chunk);
    }
    Wide::from_limbs(limbs)
}

/// The rounding direction as the boundary's code.
const fn direction(rounding: Rounding) -> u32 {
    match rounding {
        Rounding::Down => 0,
        Rounding::Up => 1,
    }
}

/// The [`Address`] thirty-two bytes name.
///
/// Called by generated prologues on the bytes an address register
/// holds. The kernel built them by evaluating the declaration, so a
/// malformed address is a defect and the trap is the deterministic
/// answer to it.
///
/// # Panics
///
/// On bytes that do not name an address class, or are not thirty-two.
#[must_use]
pub fn address_from(bytes: &[u8]) -> Address {
    let bytes: [u8; 32] = bytes.try_into().expect("an address is thirty-two bytes");
    Address::from_bytes(bytes).expect("an address names a class")
}

/// Collects input register `index` as the ids it holds: `len` bytes of
/// little-endian `u64`s, eight each.
///
/// Called by generated prologues, once per id parameter.
#[must_use]
#[inline(never)]
pub fn arg_ids(index: u32, len: u32) -> Vec<u64> {
    let mut ids = vec![0u64; (len / 8) as usize];
    // SAFETY: the register holds exactly `len` bytes, and the vector has
    // room for them; the boundary carries ids little-endian, which is
    // the guest's own byte order.
    unsafe { abi_arg(index, room(ids.as_mut_ptr())) };
    ids
}

/// `a * b / c`, the product held whole and rounded once.
#[must_use]
#[inline]
pub fn mul_div(a: Wide, b: Wide, c: Wide, rounding: Rounding) -> Wide {
    let (a, b, c) = (raised(a), raised(b), raised(c));
    let mut out = [0u8; 32];
    // SAFETY: four thirty-two byte buffers at their pointers.
    unsafe {
        math_mul_div(
            ptr(a.as_ptr()),
            ptr(b.as_ptr()),
            ptr(c.as_ptr()),
            direction(rounding),
            room(out.as_mut_ptr()),
        );
    }
    lowered(&out)
}

/// `floor(sqrt(a * b))`, the product held whole.
#[must_use]
#[inline]
pub fn geometric_mean(a: Wide, b: Wide) -> Wide {
    let (a, b) = (raised(a), raised(b));
    let mut out = [0u8; 32];
    // SAFETY: three thirty-two byte buffers at their pointers.
    unsafe { math_geometric_mean(ptr(a.as_ptr()), ptr(b.as_ptr()), room(out.as_mut_ptr())) };
    lowered(&out)
}

/// `(an/ad) * (bn/bd)`, as a fraction in the same width.
#[must_use]
#[inline]
pub fn fraction_compose(an: Wide, ad: Wide, bn: Wide, bd: Wide) -> (Wide, Wide) {
    let (an, ad, bn, bd) = (raised(an), raised(ad), raised(bn), raised(bd));
    let (mut num, mut den) = ([0u8; 32], [0u8; 32]);
    // SAFETY: six thirty-two byte buffers at their pointers.
    unsafe {
        math_fraction_compose(
            ptr(an.as_ptr()),
            ptr(ad.as_ptr()),
            ptr(bn.as_ptr()),
            ptr(bd.as_ptr()),
            room(num.as_mut_ptr()),
            room(den.as_mut_ptr()),
        );
    }
    (lowered(&num), lowered(&den))
}

/// `base` raised to `exp` at the protocol's fixed scale, by squaring.
#[must_use]
#[inline]
pub fn fixed_pow(base: Wide, exp: u32, rounding: Rounding) -> Wide {
    let base = raised(base);
    let mut out = [0u8; 32];
    // SAFETY: two thirty-two byte buffers at their pointers.
    unsafe {
        math_fixed_pow(
            ptr(base.as_ptr()),
            exp,
            direction(rounding),
            room(out.as_mut_ptr()),
        )
    };
    lowered(&out)
}

/// `an/ad` against `bn/bd`, compared at a width their cross-products fit.
#[must_use]
#[inline]
pub fn fraction_cmp(an: Wide, ad: Wide, bn: Wide, bd: Wide) -> core::cmp::Ordering {
    let (an, ad, bn, bd) = (raised(an), raised(ad), raised(bn), raised(bd));
    // SAFETY: four thirty-two byte buffers at their pointers.
    let order = unsafe {
        math_fraction_cmp(
            ptr(an.as_ptr()),
            ptr(ad.as_ptr()),
            ptr(bn.as_ptr()),
            ptr(bd.as_ptr()),
        )
    };
    match order {
        0 => core::cmp::Ordering::Less,
        1 => core::cmp::Ordering::Equal,
        _ => core::cmp::Ordering::Greater,
    }
}

/// Split `value` off a bucket, as a bucket.
#[must_use]
pub fn bucket_take(funds: &BucketHandle, value: u128) -> BucketHandle {
    let amount = amount(value);
    // SAFETY: a sixteen byte buffer at its pointer.
    BucketHandle(unsafe { state_bucket_take(funds.0, ptr(amount.as_ptr())) })
}

/// Split `num/den` off a bucket, as a bucket.
#[must_use]
pub fn bucket_split(funds: &BucketHandle, num: Wide, den: Wide) -> BucketHandle {
    let (num, den) = (raised(num), raised(den));
    // SAFETY: two thirty-two byte buffers at their pointers.
    BucketHandle(unsafe { state_bucket_split(funds.0, ptr(num.as_ptr()), ptr(den.as_ptr())) })
}

/// Merge `other` into a bucket, consuming it.
pub fn bucket_put(funds: &BucketHandle, other: BucketHandle) {
    // SAFETY: a plain scalar call.
    unsafe { state_bucket_put(funds.0, other.into_rep()) };
}

/// What a bucket carries, read through a borrow of the handle.
#[must_use]
pub fn bucket_amount(funds: &BucketHandle) -> u128 {
    let mut out = [0u8; 16];
    // SAFETY: a sixteen byte buffer at its pointer.
    unsafe { state_bucket_amount(funds.0, room(out.as_mut_ptr())) };
    u128::from_le_bytes(out)
}

/// The substate this handle reads.
#[must_use]
#[inline]
pub fn cell_get(handle: Handle) -> Vec<u8> {
    // SAFETY: a plain scalar call.
    let len = unsafe { state_site_get(handle.site, handle.element) };
    take(len)
}

/// What this handle's amount cell holds.
///
/// Beside [`cell_get`] rather than inside it: a cell holding value has
/// no byte surface, so the two answer different questions and neither is
/// the other's special case.
#[must_use]
#[inline]
pub fn cell_balance(handle: Handle) -> u128 {
    let mut out = [0u8; 16];
    // SAFETY: a sixteen byte buffer at its pointer.
    unsafe { state_site_balance(handle.site, handle.element, room(out.as_mut_ptr())) };
    u128::from_le_bytes(out)
}

/// Replace the substate this handle holds exclusively.
#[inline]
pub fn cell_set(handle: Handle, value: &[u8]) {
    // SAFETY: the slice is `len` bytes at `ptr`.
    unsafe { state_site_set(handle.site, handle.element, ptr(value.as_ptr()), len(value)) };
}

/// Seal this handle's cell on the epoch now running.
#[inline]
pub fn cell_seal(handle: Handle) {
    // SAFETY: a plain scalar call.
    unsafe { state_site_seal(handle.site, handle.element) };
}

/// The draw the seal in this handle's cell matures into.
#[must_use]
#[inline]
pub fn cell_open_seal(handle: Handle) -> Drawn {
    let mut word = [0u8; SEED_BYTES];
    // SAFETY: a thirty-two byte buffer at its pointer.
    let tag = unsafe { state_site_open_seal(handle.site, handle.element, room(word.as_mut_ptr())) };
    match tag {
        0 => Drawn::Pending,
        1 => Drawn::Ready(word),
        _ => Drawn::Expired,
    }
}

/// End this handle's cell, so nothing is there.
#[inline]
pub fn cell_clear(handle: Handle) {
    // SAFETY: a plain scalar call.
    unsafe { state_site_clear(handle.site, handle.element) };
}

/// Credit this handle's amount cell with what the bucket carries.
#[inline]
pub fn cell_put(handle: Handle, funds: BucketHandle) {
    // SAFETY: a plain scalar call.
    unsafe { state_site_put(handle.site, handle.element, funds.into_rep()) };
}

/// Debit this handle's amount cell, as a bucket.
#[must_use]
#[inline]
pub fn cell_take(handle: Handle, value: u128) -> BucketHandle {
    let amount = amount(value);
    // SAFETY: a sixteen byte buffer at its pointer.
    BucketHandle(unsafe { state_site_take(handle.site, handle.element, ptr(amount.as_ptr())) })
}

/// Take the reservation this method declared.
#[must_use]
#[inline]
pub fn reserve_take(handle: Handle) -> BucketHandle {
    // SAFETY: a plain scalar call.
    BucketHandle(unsafe { state_site_reserve_take(handle.site, handle.element) })
}

/// Create `value` of what the grant at `grant` names.
#[must_use]
#[inline]
pub fn mint(grant: u32, value: u128) -> BucketHandle {
    let amount = amount(value);
    // SAFETY: a sixteen byte buffer at its pointer.
    BucketHandle(unsafe { state_mint(grant, ptr(amount.as_ptr())) })
}

/// Create the named instances of what the grant at `grant` names.
#[must_use]
#[inline]
pub fn mint_instances(grant: u32, ids: &[u64]) -> BucketHandle {
    // SAFETY: the slice is `count` little-endian `u64`s at `ptr`.
    BucketHandle(unsafe { state_mint_instances(grant, ptr(ids.as_ptr()), count(ids)) })
}

/// Destroy value this invocation was granted, consuming the bucket.
#[inline]
pub fn burn(funds: BucketHandle) {
    // SAFETY: a plain scalar call.
    unsafe { state_burn(funds.into_rep()) };
}

/// Entries currently in this interval, bounded by its declared cap.
#[must_use]
#[inline]
pub fn entry_count(handle: Handle) -> u32 {
    // SAFETY: a plain scalar call.
    unsafe { state_site_count(handle.site, handle.element) }
}

/// Whether this interval's page holds every entry the interval does.
#[must_use]
#[inline]
pub fn entry_covered(handle: Handle) -> bool {
    // SAFETY: a plain scalar call.
    unsafe { state_site_covered(handle.site, handle.element) != 0 }
}

/// The order key of this interval's entry at `index`.
///
/// An exclusive interval reads its own keys: the write subsumes the
/// read, so walking one by order costs no second declaration.
#[must_use]
#[inline]
pub fn entry_order(handle: Handle, index: u32) -> OrderKey {
    let mut out = [0u8; 16];
    // SAFETY: a sixteen byte buffer at its pointer.
    unsafe { state_site_order(handle.site, handle.element, index, room(out.as_mut_ptr())) };
    OrderKey::from_bits(u128::from_le_bytes(out))
}

/// The value of this interval's entry at `index`.
#[must_use]
#[inline]
pub fn entry_get(handle: Handle, index: u32) -> Vec<u8> {
    // SAFETY: a plain scalar call.
    let len = unsafe { state_site_entry(handle.site, handle.element, index) };
    take(len)
}

/// The value of this interval's entry at `order`, or nothing if the
/// interval holds none.
///
/// An absent entry and an entry holding empty bytes are deliberately
/// one answer: an entry's presence is carried by its value, so a body
/// that must tell them apart stores a non-empty encoding.
#[must_use]
#[inline]
pub fn entry_at(handle: Handle, order: OrderKey) -> Vec<u8> {
    (0..entry_count(handle))
        .find(|&index| entry_order(handle, index) == order)
        .map_or_else(Vec::new, |index| entry_get(handle, index))
}

/// Replace this interval's entry at `index`.
#[inline]
pub fn entry_set(handle: Handle, index: u32, value: &[u8]) {
    // SAFETY: the slice is `len` bytes at `ptr`.
    unsafe {
        state_site_entry_set(
            handle.site,
            handle.element,
            index,
            ptr(value.as_ptr()),
            len(value),
        );
    }
}

/// Insert (or replace) this interval's entry at `order`.
#[inline]
pub fn entry_insert(handle: Handle, order: OrderKey, value: &[u8]) {
    let order = amount(order.bits());
    // SAFETY: a sixteen byte buffer and a slice, each at its pointer.
    unsafe {
        state_site_insert(
            handle.site,
            handle.element,
            ptr(order.as_ptr()),
            ptr(value.as_ptr()),
            len(value),
        );
    }
}

/// File every instance the bucket carries as an entry of this interval.
#[inline]
pub fn entry_put(handle: Handle, funds: BucketHandle, value: &[u8]) {
    // SAFETY: the slice is `len` bytes at `ptr`.
    unsafe {
        state_site_instance_put(
            handle.site,
            handle.element,
            funds.into_rep(),
            ptr(value.as_ptr()),
            len(value),
        );
    }
}

/// Take the named entries of this interval, as the instances they were.
#[must_use]
#[inline]
pub fn entry_take(handle: Handle, ids: &[u64]) -> BucketHandle {
    // SAFETY: the slice is `count` little-endian `u64`s at `ptr`.
    BucketHandle(unsafe {
        state_site_instance_take(handle.site, handle.element, ptr(ids.as_ptr()), count(ids))
    })
}

/// Remove this interval's entry at `index`.
#[inline]
pub fn entry_remove(handle: Handle, index: u32) {
    // SAFETY: a plain scalar call.
    unsafe { state_site_remove(handle.site, handle.element, index) };
}

/// How many elements the site covers.
///
/// The element count rather than the count of expansions that fired, so
/// a body walks the same indices whichever of its sites it is reading —
/// and a site that did not fire reads as undeclared rather than
/// shortening the walk.
#[must_use]
#[inline]
pub fn site_len(rep: u32) -> u32 {
    // SAFETY: a plain scalar call.
    unsafe { state_site_len(rep) }
}

/// Whether the site declared anything for the element at `index`.
#[must_use]
#[inline]
pub fn site_declared(rep: u32, index: u32) -> bool {
    // SAFETY: a plain scalar call.
    unsafe { state_site_declared(rep, index) != 0 }
}

/// The transaction clock, in milliseconds.
#[must_use]
pub fn clock_ms() -> u64 {
    // SAFETY: a plain scalar call.
    unsafe { env_clock() }
}

/// The protocol hash function.
#[must_use]
pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 32];
    // SAFETY: a slice and a thirty-two byte buffer, each at its pointer.
    unsafe { crypto_hash(ptr(data.as_ptr()), len(data), room(out.as_mut_ptr())) };
    out.to_vec()
}

/// Emit one event of the package's own type index.
pub fn emit(event_type: u32, payload: &[u8]) {
    // SAFETY: the slice is `len` bytes at `ptr`.
    unsafe { events_emit(event_type, ptr(payload.as_ptr()), len(payload)) };
}
