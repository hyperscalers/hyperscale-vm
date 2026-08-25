//! The kernel a contract body executes against on the host.
//!
//! The counterpart of `crate::guest`: the same operations, resolved to
//! a [`KernelHost`] the caller installed instead of to the imports a
//! component links. What a body is written in does not change, which is
//! the whole point — the accessors in [`crate::state`] pick one of these
//! two, and the text between them is the author's.
//!
//! # The kernel arrives ambiently
//!
//! An accessor is `&self` with no kernel parameter, because threading one
//! through would put it into the author's text: `self.vaults.at(k)` would
//! have to become `self.vaults.at(kernel, k)` in every contract ever
//! written. So [`with_kernel`] installs one for the duration of an
//! invocation and takes it back afterwards.
//!
//! That is sound because an invocation cannot nest. The kernel's world
//! has no call import — a manifest's nodes are walked one at a time by
//! the kernel itself, and a body reaches another package by returning,
//! never by calling — so there is never a second kernel wanting the slot
//! a first one holds. [`with_kernel`] refuses rather than assumes it: a
//! scope opened inside a scope is a defect in whoever opened it, and a
//! silent overwrite would be the kind that is found much later.
//!
//! # A refusal is a trap
//!
//! Every kernel operation can refuse deterministically, and in a guest
//! that refusal is a trap: the engine unwinds the invocation and the
//! class rides out to the receipt. There is no engine here, so the panic
//! *is* the unwind, and [`Refusal`] is what it carries — a class rather
//! than a message, on the same terms both engines report one.

use core::any::Any;
use core::cell::RefCell;

use hyperscale_vm_embed::KernelHost;
pub use hyperscale_vm_embed::{GuestArg, Invoked};
use hyperscale_vm_types::{AbortReason, Address, Drawn, math};

use crate::handle::Handle;
use crate::num::{Rounding, Wide};
use crate::state::{Bucket, NfBucket, OrderKey};

/// A kernel refusal, in flight through the unwind that carries it.
///
/// Panicked rather than returned, because an accessor's signature is the
/// guest's — a body that had to handle a refusal here would be a body
/// that could not be compiled to wasm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal(pub AbortReason);

/// A kernel a body can be run against.
///
/// `Any` beside the surface so the scope can hand back what it was
/// given: an engine embedding needs its own host type returned, not a
/// trait object it would have to guess the shape of.
pub trait Kernel: KernelHost + Any {}
impl<T: KernelHost + Any> Kernel for T {}

thread_local! {
    static KERNEL: RefCell<Option<Box<dyn Kernel>>> = const { RefCell::new(None) };
}

/// The installed kernel's lifetime, as a value that owns clearing the
/// slot.
///
/// A guard rather than a pair of statements, because the scope has to end
/// however the body does. An unwind past it has no kernel to hand back —
/// the frame that would have received one is going away — but leaving the
/// slot filled would poison the thread for every later invocation, and the
/// failure that produced would name the scope that met the mess rather
/// than the one that made it.
struct Scope;

impl Scope {
    /// Install `kernel`, refusing a scope already open.
    ///
    /// Checked before installing: the refusal reports a defect, and one
    /// that dropped the kernel it interrupted on the way would turn a
    /// diagnosable mistake into two.
    fn open(kernel: Box<dyn Kernel>) -> Self {
        KERNEL.with_borrow_mut(|slot| {
            assert!(
                slot.is_none(),
                "an invocation is already running on this thread"
            );
            *slot = Some(kernel);
        });
        Self
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        KERNEL.with_borrow_mut(Option::take);
    }
}

/// The installed kernel, out of the slot.
///
/// # Panics
///
/// Outside a scope, which only the scope itself calls this from.
fn uninstall() -> Box<dyn Kernel> {
    KERNEL
        .with_borrow_mut(Option::take)
        .expect("the scope holds the kernel it installed")
}

/// Run `body` with `kernel` reachable from every accessor it calls, and
/// give the kernel back.
///
/// A body that unwinds takes the kernel with it: there is no value to
/// return it in. The thread is left as it was found either way, so the
/// next invocation on it starts from an empty slot.
///
/// # Panics
///
/// If a scope is already open on this thread, which an invocation cannot
/// do to itself and a caller should not do at all.
pub fn with_kernel<H: Kernel, R>(kernel: H, body: impl FnOnce() -> R) -> (H, R) {
    // Bound, not discarded: the guard has to outlive the body for an
    // unwind through it to reach the drop that clears the slot.
    let _scope = Scope::open(Box::new(kernel));
    let value = body();
    let kernel = (uninstall() as Box<dyn Any>)
        .downcast::<H>()
        .expect("the kernel that comes back is the one that went in");
    (*kernel, value)
}

/// The installed kernel, for one operation.
///
/// # Panics
///
/// Outside an invocation, where there is no kernel to answer — a body
/// called directly rather than through the walk that materializes its
/// capabilities.
fn kernel<R>(operation: impl FnOnce(&mut dyn KernelHost) -> R) -> R {
    KERNEL.with_borrow_mut(|slot| {
        let installed = slot
            .as_deref_mut()
            .expect("a contract body reached the kernel outside an invocation");
        operation(installed)
    })
}

/// A deterministic refusal, as the unwind that carries it.
fn refuse(reason: AbortReason) -> ! {
    std::panic::panic_any(Refusal(reason))
}

/// The value a kernel operation answered with, or the trap it refused
/// with.
fn settled<T>(answer: Result<T, AbortReason>) -> T {
    answer.unwrap_or_else(|reason| refuse(reason))
}

/// Take what materializing an interval lifted out of the store.
///
/// Every range operation asks, because every one of them can reach a
/// scan and the session refuses to finish still owing. The figure is
/// dropped rather than charged: an engine prices those bytes as fuel,
/// and this path has none. Asked before a refusal propagates, because
/// the page was read either way.
fn scanned<T>(answer: Result<T, AbortReason>) -> T {
    kernel(|k| k.take_scan_debt());
    settled(answer)
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
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_get(site, element)))
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
pub fn cell_balance(handle: Handle) -> u128 {
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_balance(site, element)))
}

/// Replace the substate this handle holds exclusively.
///
/// # Panics
///
/// On any mode but [`Handle::Write`].
pub fn cell_set(handle: Handle, value: &[u8]) {
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_set(site, element, value.to_vec())));
}

/// Seal this handle's cell on the epoch now running.
///
/// # Panics
///
/// On a handle that holds no exclusive write, which the declaration a
/// seal is written through rules out.
pub fn cell_seal(handle: Handle) {
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_seal(site, element)));
}

/// The draw the seal in this handle's cell matured into.
///
/// # Panics
///
/// On a handle that holds no exclusive write, which the declaration a
/// seal is read through rules out.
#[must_use]
pub fn cell_open_seal(handle: Handle) -> Drawn {
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_open_seal(site, element)))
}

/// End the substate this handle holds exclusively.
///
/// # Panics
///
/// On any mode but [`Handle::Write`].
pub fn cell_clear(handle: Handle) {
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_clear(site, element)));
}

/// Move value into this handle's amount cell, consuming the bucket.
///
/// # Panics
///
/// On a handle whose mode moves no value.
pub fn cell_put(handle: Handle, funds: u32) {
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_put(site, element, funds)));
}

/// Move value out of this handle's amount cell.
///
/// # Panics
///
/// On a handle whose mode moves no value.
#[must_use]
pub fn cell_take(handle: Handle, value: u128) -> u32 {
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_take(site, element, value)))
}

/// Take the reservation this method declared.
///
/// # Panics
///
/// On any mode but [`Handle::Reserve`].
#[must_use]
pub fn reserve_take(handle: Handle) -> u32 {
    let Handle { site, element } = handle;
    settled(kernel(|k| k.site_reserve_take(site, element)))
}

/// Issue `value` of the resource the grant at `grant` names.
#[must_use]
pub fn mint(grant: u32, value: u128) -> u32 {
    settled(kernel(|k| k.mint(grant, value)))
}

/// Create the named instances of the resource the grant at `grant`
/// names.
#[must_use]
pub fn mint_instances(grant: u32, ids: &[u64]) -> u32 {
    settled(kernel(|k| k.mint_instances(grant, ids)))
}

/// Destroy what the bucket at `funds` carries, against the grant at `rep`.
pub fn burn(funds: u32) {
    settled(kernel(|k| k.burn(funds)));
}

/// A wide word as the arithmetic's own type.
///
/// Written out rather than a `From` impl: the vocabulary's type is this
/// crate's and the arithmetic's is not, so the conversion has nowhere to
/// live but here.
const fn widened(value: Wide) -> math::U256 {
    math::U256::from_limbs(value.limbs())
}

/// The arithmetic's answer as the vocabulary holds it.
const fn narrowed(value: math::U256) -> Wide {
    Wide::from_limbs(value.limbs())
}

/// `a * b / c`, the product held whole and rounded once.
///
/// The native lane reaches the same functions the two engines do, rather
/// than a second implementation beside them: what a guest calls through
/// `hyperscale:kernel/math` and what an author's fast lane calls here are
/// one body, so the lane cannot disagree with the artifact about money.
///
/// # Panics
///
/// On a zero divisor and on a result past the amount width — the same
/// refusals the boundary raises, in the shape a host body raises them.
#[must_use]
pub fn mul_div(a: Wide, b: Wide, c: Wide, rounding: Rounding) -> Wide {
    narrowed(
        math::mul_div(widened(a), widened(b), widened(c), rounding)
            .expect("a well-formed wide multiplication"),
    )
}

/// `floor(sqrt(a * b))`, the product held whole.
#[must_use]
pub fn geometric_mean(a: Wide, b: Wide) -> Wide {
    narrowed(math::geometric_mean(widened(a), widened(b)))
}

/// `(an/ad) * (bn/bd)`, as a fraction in the same width.
///
/// # Panics
///
/// On a zero denominator and where the product does not fit reduced.
#[must_use]
pub fn fraction_compose(an: Wide, ad: Wide, bn: Wide, bd: Wide) -> (Wide, Wide) {
    let (num, den) = math::fraction_compose(widened(an), widened(ad), widened(bn), widened(bd))
        .expect("a well-formed fraction composition");
    (narrowed(num), narrowed(den))
}

/// `an/ad` against `bn/bd`, at a width their cross-products fit.
///
/// # Panics
///
/// On a zero denominator.
#[must_use]
pub fn fraction_cmp(an: Wide, ad: Wide, bn: Wide, bd: Wide) -> core::cmp::Ordering {
    math::fraction_cmp(widened(an), widened(ad), widened(bn), widened(bd))
        .expect("a well-formed fraction comparison")
}

/// `base` raised to `exp` at the protocol's fixed scale.
///
/// # Panics
///
/// Where any intermediate leaves the wide width.
#[must_use]
pub fn fixed_pow(base: Wide, exp: u32, rounding: Rounding) -> Wide {
    narrowed(math::fixed_pow(widened(base), exp, rounding).expect("a well-formed exponentiation"))
}

/// Split `value` off a bucket, as a bucket.
#[must_use]
pub fn bucket_take(rep: u32, value: u128) -> u32 {
    settled(kernel(|k| k.bucket_take(rep, value)))
}

/// Split `num/den` off a bucket, as a bucket.
#[must_use]
pub fn bucket_split(rep: u32, num: Wide, den: Wide) -> u32 {
    settled(kernel(|k| k.bucket_split(rep, widened(num), widened(den))))
}

/// Merge one bucket into another, consuming it.
pub fn bucket_put(rep: u32, other: u32) {
    settled(kernel(|k| k.bucket_put(rep, other)));
}

/// What a bucket carries.
#[must_use]
pub fn bucket_amount(rep: u32) -> u128 {
    settled(kernel(|k| k.bucket_amount(rep)))
}

/// Entries currently visible in this interval, bounded by its cap.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
pub fn entry_count(handle: Handle) -> u32 {
    let Handle { site, element } = handle;
    scanned(kernel(|k| k.site_count(site, element)))
}

/// Whether this interval's page holds every entry the interval does.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
pub fn entry_covered(handle: Handle) -> bool {
    let Handle { site, element } = handle;
    scanned(kernel(|k| k.site_covered(site, element)))
}

/// The order key of this interval's entry at `index`.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
pub fn entry_order(handle: Handle, index: u32) -> OrderKey {
    let Handle { site, element } = handle;
    // The kernel orders by the packed integer and knows nothing of what
    // was packed into it, so the type is put back on at this seam.
    OrderKey::from_bits(scanned(kernel(|k| k.site_order(site, element, index))))
}

/// The value of this interval's entry at `index`.
///
/// # Panics
///
/// On a handle that is not an interval.
#[must_use]
pub fn entry_get(handle: Handle, index: u32) -> Vec<u8> {
    let Handle { site, element } = handle;
    scanned(kernel(|k| k.site_entry(site, element, index)))
}

/// The value of the entry at `order`, or empty where there is none.
#[must_use]
pub fn entry_at(handle: Handle, order: OrderKey) -> Vec<u8> {
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
    let Handle { site, element } = handle;
    scanned(kernel(|k| {
        k.site_entry_set(site, element, index, value.to_vec())
    }));
}

/// Insert into this interval at `order`.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
pub fn entry_insert(handle: Handle, order: OrderKey, value: &[u8]) {
    let Handle { site, element } = handle;
    scanned(kernel(|k| {
        k.site_insert(site, element, order.bits(), value.to_vec())
    }));
}

/// File the instances a bucket carries into this interval.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
pub fn entry_put(handle: Handle, funds: u32, value: &[u8]) {
    let Handle { site, element } = handle;
    scanned(kernel(|k| {
        k.site_instance_put(site, element, funds, value.to_vec())
    }));
}

/// Take the instances `ids` names out of this interval.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
#[must_use]
pub fn entry_take(handle: Handle, ids: &[u64]) -> u32 {
    let Handle { site, element } = handle;
    scanned(kernel(|k| k.site_instance_take(site, element, ids)))
}

/// Remove this interval's entry at `index`.
///
/// # Panics
///
/// On any mode but [`Handle::RangeWrite`].
pub fn entry_remove(handle: Handle, index: u32) {
    let Handle { site, element } = handle;
    scanned(kernel(|k| k.site_remove(site, element, index)));
}

/// The transaction clock, in milliseconds.
#[must_use]
pub fn clock_ms() -> u64 {
    kernel(|k| k.clock_ms())
}

/// The protocol hash function.
#[must_use]
pub fn hash(data: &[u8]) -> Vec<u8> {
    kernel(|k| k.hash(data)).to_vec()
}

/// Emit one event of the package's own type index.
pub fn emit(event_type: u32, payload: &[u8]) {
    settled(kernel(|k| k.emit(event_type, payload.to_vec())));
}

/// One export invocation, driven against `kernel`.
///
/// The scope, the unwind and the classification in one place, because a
/// generated dispatch should carry no policy: what a panic means, and
/// what comes back when one happens, is the same answer for every
/// package.
///
/// A body that panics is a body that trapped — the engines' own reading
/// of `unreachable`, which is what an `assert!`, a failed `expect` and an
/// arithmetic overflow all compile to. The kernel comes back either way,
/// because the caller needs it for the rollback.
pub fn dispatch<K: Kernel>(kernel: K, body: impl FnOnce() -> Invoked) -> (K, Invoked) {
    with_kernel(kernel, || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or_else(|payload| {
            Invoked::Aborted(
                payload
                    .downcast_ref::<Refusal>()
                    .map_or(AbortReason::Unreachable, |refusal| refusal.0),
            )
        })
    })
}

/// The export the call named does not exist on this package.
#[must_use]
pub const fn no_such_export() -> Invoked {
    Invoked::Aborted(AbortReason::AbiViolation)
}

/// The argument at `at`, or the violation of having been handed none.
fn arg<'a>(args: &'a [GuestArg<'a>], at: usize) -> &'a GuestArg<'a> {
    args.get(at)
        .unwrap_or_else(|| refuse(AbortReason::AbiViolation))
}

/// The site at `at`.
///
/// An argument of the wrong shape is the canonical ABI's own violation,
/// reached here by the same route: the export's parameter list is a
/// function of its signature, so anything but a site here is a
/// composition that never should have been assembled. What the
/// capability the site reaches grants is the kernel's answer, held at
/// the operation rather than here.
#[must_use]
pub fn handle(args: &[GuestArg<'_>], at: usize) -> u32 {
    let GuestArg::Site { site } = *arg(args, at) else {
        refuse(AbortReason::AbiViolation)
    };
    site
}

/// How many elements the site covers.
#[must_use]
pub fn site_len(site: u32) -> u32 {
    settled(kernel(|k| k.site_len(site)))
}

/// Whether the site declared anything for the element at `element`.
#[must_use]
pub fn site_declared(site: u32, element: u32) -> bool {
    settled(kernel(|k| k.site_declared(site, element)))
}

/// The scalar at `at`.
#[must_use]
pub fn scalar(args: &[GuestArg<'_>], at: usize) -> u64 {
    match *arg(args, at) {
        GuestArg::U64(value) => value,
        _ => refuse(AbortReason::AbiViolation),
    }
}

/// Whether the clause the parameter at `at` speaks for was declared.
///
/// The declaration's own verdict, reached once by the evaluation routing
/// already ran. A body branches on this rather than on a second copy of
/// the condition, so the two cannot disagree — and taking the other
/// branch reaches a capability nothing materialized.
#[must_use]
pub fn flag(args: &[GuestArg<'_>], at: usize) -> bool {
    match *arg(args, at) {
        GuestArg::Bool(taken) => taken,
        _ => refuse(AbortReason::AbiViolation),
    }
}

/// The address at `at`.
#[must_use]
pub fn address(args: &[GuestArg<'_>], at: usize) -> Address {
    match *arg(args, at) {
        GuestArg::Address(address) => address,
        _ => refuse(AbortReason::AbiViolation),
    }
}

/// The cell-encoded value at `at`, for the vocabulary to decode.
#[must_use]
pub fn cell<'a>(args: &'a [GuestArg<'a>], at: usize) -> &'a [u8] {
    match *arg(args, at) {
        GuestArg::Bytes(bytes) => bytes,
        _ => refuse(AbortReason::AbiViolation),
    }
}

/// The id set at `at`, as the ids it is.
#[must_use]
pub fn ids<'a>(args: &'a [GuestArg<'a>], at: usize) -> &'a [u64] {
    match *arg(args, at) {
        GuestArg::Ids(ids) => ids,
        _ => refuse(AbortReason::AbiViolation),
    }
}

/// The value edge at `at`, as the bucket a body holds it as.
#[must_use]
pub fn edge(args: &[GuestArg<'_>], at: usize) -> Bucket {
    match *arg(args, at) {
        GuestArg::Bucket(rep) => Bucket::at(rep),
        _ => refuse(AbortReason::AbiViolation),
    }
}

/// The non-fungible edge at `at`, as the instances it carries.
#[must_use]
pub fn nf_edge(args: &[GuestArg<'_>], at: usize) -> NfBucket {
    match *arg(args, at) {
        GuestArg::Bucket(rep) => NfBucket::at(rep),
        _ => refuse(AbortReason::AbiViolation),
    }
}
