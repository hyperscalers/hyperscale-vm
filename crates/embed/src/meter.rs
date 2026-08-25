//! The boundary cost model, stated once.
//!
//! Engine fuel meters guest instructions but is blind to boundary copies —
//! a value crossing the canonical ABI moves bytes the instruction schedule
//! never sees. Every kernel-world function therefore carries a supplement:
//! argument bytes before the host operation, result bytes after it
//! succeeds, and for the interval functions a second supplement for what a
//! scan lifted out of the store — bytes that never cross the ABI and so
//! are invisible to the first, charged whether the call then succeeds or
//! refuses, because the page was read either way.
//!
//! The functions here are that supplement: one per world function, each
//! owning its prices *and* the order they interleave with the host
//! operation, over two capabilities an engine adapts to — [`FuelSink`],
//! the budget, and [`HostAccess`], the kernel behind the call. Shared
//! rather than specified, on the same argument as
//! [`hyperscale_vm_types::math`]: two
//! engines that each restated thirty charge sequences would drift one arm
//! at a time, and a missed or reordered charge is a consensus fuel
//! divergence only a corpus case reaching that exact arm could catch.

// Every function fails the one way: [`MeterError`], exhaustion or the
// kernel's refusal class. Stated on the type rather than thirty times.
#![allow(clippy::missing_errors_doc)]

use core::cmp::Ordering;

use hyperscale_vm_types::math::{self, Rounding, U256};
use hyperscale_vm_types::{AbortReason, Drawn, SEED_BYTES};

use crate::KernelHost;

/// Fuel charged per byte crossing the canonical ABI boundary.
pub const FUEL_PER_BOUNDARY_BYTE: u64 = 1;

/// What an amount costs at the boundary.
///
/// The width it has, not the width it travels in: a flat record copies
/// nothing through linear memory, and pricing it at zero would make a
/// movement's fee turn on the encoding rather than on the value crossing.
pub const AMOUNT_BOUNDARY_BYTES: usize = 16;

/// What a wide word costs at the boundary: the width it has.
pub const WIDE_BOUNDARY_BYTES: usize = 32;

/// The budget cannot cover a charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exhausted;

/// The fuel budget a metered call draws on.
///
/// One number governs the transaction: an engine implements this over the
/// same counter its instruction schedule charges, so boundary debt is
/// visible to its own exhaustion checks.
pub trait FuelSink {
    /// Deducts `fuel` from the budget.
    ///
    /// # Errors
    ///
    /// [`Exhausted`] when the budget cannot cover the charge. Strict: an
    /// exact-fit charge passes with nothing left, and it is the next
    /// instruction check that exhausts.
    fn consume(&mut self, fuel: u64) -> Result<(), Exhausted>;
}

/// The kernel behind a metered call.
pub trait HostAccess {
    /// The host the engine threads through its store.
    type Host: KernelHost;

    /// The host, to perform one operation on.
    fn host(&mut self) -> &mut Self::Host;
}

/// How a metered call failed: the budget ran out, or the kernel refused
/// with its own class. An engine maps each onto its native trap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeterError {
    /// The budget cannot cover a boundary charge.
    Exhausted,
    /// A deterministic kernel refusal, carrying the host's class.
    Refused(AbortReason),
}

fn charge(sink: &mut impl FuelSink, bytes: usize) -> Result<(), MeterError> {
    let cost = (bytes as u64).saturating_mul(FUEL_PER_BOUNDARY_BYTE);
    sink.consume(cost)
        .map_err(|Exhausted| MeterError::Exhausted)
}

fn refused<T>(answer: Result<T, AbortReason>) -> Result<T, MeterError> {
    answer.map_err(MeterError::Refused)
}

/// Charges what the call just made lifted out of the store by scanning.
///
/// Asked before the call's own refusal propagates, because the page was
/// read either way: an index the scan does not contain is a refusal the
/// scan had to happen to reach.
fn charge_scan<P: HostAccess + FuelSink>(port: &mut P) -> Result<(), MeterError> {
    let lifted = port.host().take_scan_debt();
    charge(port, lifted)
}

/// `site.len`.
///
/// Nothing crosses the boundary but the count itself, which every host
/// call already carries the cost of.
pub fn site_len<P: HostAccess + FuelSink>(port: &mut P, site: u32) -> Result<u32, MeterError> {
    refused(port.host().site_len(site))
}

/// `site.declared`.
pub fn site_declared<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<bool, MeterError> {
    refused(port.host().site_declared(site, element))
}

/// `access.get`.
pub fn cell_get<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<Vec<u8>, MeterError> {
    let value = refused(port.host().cell_get(site, element))?;
    charge(port, value.len())?;
    Ok(value)
}

/// `access.set`.
pub fn cell_set<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    value: Vec<u8>,
) -> Result<(), MeterError> {
    charge(port, value.len())?;
    refused(port.host().write_cell_set(site, element, value))
}

/// `access.clear`. Nothing crosses the boundary, so nothing is
/// charged for crossing it — the leaf's removal is the store's work,
/// which the write capability was already provisioned for.
pub fn cell_clear<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<(), MeterError> {
    refused(port.host().write_cell_clear(site, element))
}

/// `mint`. Charges its amount argument and nothing for the handle it
/// yields: a bucket crosses as a table index, where the amount it carries
/// never crosses at all — here and for every take below.
pub fn mint<P: HostAccess + FuelSink>(port: &mut P, amount: u128) -> Result<u32, MeterError> {
    charge(port, AMOUNT_BOUNDARY_BYTES)?;
    refused(port.host().mint(amount))
}

/// `access.balance`: one figure, whichever value mode
/// handle types.
pub fn cell_balance<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<u128, MeterError> {
    let held = refused(port.host().amount_cell_balance(site, element))?;
    charge(port, AMOUNT_BOUNDARY_BYTES)?;
    Ok(held)
}

/// `burn`.
pub fn burn<P: HostAccess + FuelSink>(port: &mut P, funds: u32) -> Result<(), MeterError> {
    refused(port.host().burn(funds))
}

/// `mint-instances`.
pub fn mint_instances<P: HostAccess + FuelSink>(
    port: &mut P,
    ids: &[u64],
) -> Result<u32, MeterError> {
    charge(port, ids.len() * 8)?;
    refused(port.host().mint_instances(ids))
}

/// `access.instance-take`.
pub fn instance_range_take<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    ids: &[u64],
) -> Result<u32, MeterError> {
    charge(port, ids.len() * 8)?;
    let taken = port.host().range_take(site, element, ids);
    charge_scan(port)?;
    refused(taken)
}

/// `access.instance-put`. Asks the store what each order already holds
/// before filing it, so it pays for the seeks like a take does.
pub fn instance_range_put<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    funds: u32,
    value: Vec<u8>,
) -> Result<(), MeterError> {
    charge(port, value.len())?;
    let filed = port.host().range_put(site, element, funds, value);
    charge_scan(port)?;
    refused(filed)
}

/// `bucket.take`.
pub fn bucket_take<P: HostAccess + FuelSink>(
    port: &mut P,
    bucket: u32,
    amount: u128,
) -> Result<u32, MeterError> {
    charge(port, AMOUNT_BOUNDARY_BYTES)?;
    refused(port.host().bucket_take(bucket, amount))
}

/// `bucket.split`.
pub fn bucket_split<P: HostAccess + FuelSink>(
    port: &mut P,
    bucket: u32,
    num: U256,
    den: U256,
) -> Result<u32, MeterError> {
    charge(port, WIDE_BOUNDARY_BYTES * 2)?;
    refused(port.host().bucket_split(bucket, num, den))
}

/// `bucket.put`.
pub fn bucket_put<P: HostAccess + FuelSink>(
    port: &mut P,
    bucket: u32,
    other: u32,
) -> Result<(), MeterError> {
    refused(port.host().bucket_put(bucket, other))
}

/// `bucket.amount`.
pub fn bucket_amount<P: HostAccess + FuelSink>(
    port: &mut P,
    bucket: u32,
) -> Result<u128, MeterError> {
    let amount = refused(port.host().bucket_amount(bucket))?;
    charge(port, AMOUNT_BOUNDARY_BYTES)?;
    Ok(amount)
}

/// `access.put`.
pub fn cell_put<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    funds: u32,
) -> Result<(), MeterError> {
    refused(port.host().cell_put(site, element, funds))
}

/// `access.take`.
pub fn cell_take<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    amount: u128,
) -> Result<u32, MeterError> {
    charge(port, AMOUNT_BOUNDARY_BYTES)?;
    refused(port.host().cell_take(site, element, amount))
}

/// `access.reserve-take`.
pub fn reserve_take<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<u32, MeterError> {
    refused(port.host().reserve_take(site, element))
}

/// `access.count`.
pub fn range_count<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<u32, MeterError> {
    let count = port.host().range_count(site, element);
    charge_scan(port)?;
    refused(count)
}

/// `access.covered`.
pub fn range_covered<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<bool, MeterError> {
    let covered = port.host().range_covered(site, element);
    charge_scan(port)?;
    refused(covered)
}

/// `access.order`.
pub fn range_order<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    index: u32,
) -> Result<u128, MeterError> {
    let order = port.host().range_order(site, element, index);
    charge_scan(port)?;
    let order = refused(order)?;
    charge(port, AMOUNT_BOUNDARY_BYTES)?;
    Ok(order)
}

/// `access.entry`.
pub fn range_entry<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    index: u32,
) -> Result<Vec<u8>, MeterError> {
    let value = port.host().range_entry(site, element, index);
    charge_scan(port)?;
    let value = refused(value)?;
    charge(port, value.len())?;
    Ok(value)
}

/// `access.entry-set`.
pub fn range_set<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    index: u32,
    value: Vec<u8>,
) -> Result<(), MeterError> {
    charge(port, value.len())?;
    let set = port.host().range_set(site, element, index, value);
    charge_scan(port)?;
    refused(set)
}

/// `access.insert`.
pub fn range_insert<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    order: u128,
    value: Vec<u8>,
) -> Result<(), MeterError> {
    charge(port, AMOUNT_BOUNDARY_BYTES + value.len())?;
    let inserted = port.host().range_insert(site, element, order, value);
    charge_scan(port)?;
    refused(inserted)
}

/// `access.remove`.
pub fn range_remove<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
    index: u32,
) -> Result<(), MeterError> {
    let removed = port.host().range_remove(site, element, index);
    charge_scan(port)?;
    refused(removed)
}

/// `math.mul-div`. The math functions reach no state, so they draw on the
/// budget alone: the shared implementation answers, the meter prices the
/// operands and the result at the width they have.
pub fn mul_div(
    sink: &mut impl FuelSink,
    a: U256,
    b: U256,
    c: U256,
    rounding: Rounding,
) -> Result<U256, MeterError> {
    charge(sink, WIDE_BOUNDARY_BYTES * 4)?;
    math::mul_div(a, b, c, rounding).map_err(|error| MeterError::Refused(error.into()))
}

/// `math.geometric-mean`.
pub fn geometric_mean(sink: &mut impl FuelSink, a: U256, b: U256) -> Result<U256, MeterError> {
    charge(sink, WIDE_BOUNDARY_BYTES * 3)?;
    Ok(math::geometric_mean(a, b))
}

/// `math.fraction-compose`.
pub fn fraction_compose(
    sink: &mut impl FuelSink,
    an: U256,
    ad: U256,
    bn: U256,
    bd: U256,
) -> Result<(U256, U256), MeterError> {
    charge(sink, WIDE_BOUNDARY_BYTES * 6)?;
    math::fraction_compose(an, ad, bn, bd).map_err(|error| MeterError::Refused(error.into()))
}

/// `math.fraction-cmp`.
pub fn fraction_cmp(
    sink: &mut impl FuelSink,
    an: U256,
    ad: U256,
    bn: U256,
    bd: U256,
) -> Result<Ordering, MeterError> {
    charge(sink, WIDE_BOUNDARY_BYTES * 4)?;
    math::fraction_cmp(an, ad, bn, bd).map_err(|error| MeterError::Refused(error.into()))
}

/// `math.fixed-pow`.
pub fn fixed_pow(
    sink: &mut impl FuelSink,
    base: U256,
    exp: u32,
    rounding: Rounding,
) -> Result<U256, MeterError> {
    charge(sink, WIDE_BOUNDARY_BYTES * 2)?;
    math::fixed_pow(base, exp, rounding).map_err(|error| MeterError::Refused(error.into()))
}

/// `state.access-seal`.
///
/// Priced as the epoch it stores, on the same terms as the set it is:
/// the leaf is eight bytes whatever epoch it names.
///
/// # Errors
///
/// A deterministic refusal (a handle that names no write).
pub fn seal<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<(), MeterError> {
    refused(port.host().seal(site, element))?;
    charge(port, size_of::<u64>())
}

/// `state.access-open-seal`.
///
/// Priced as the word it answers: the resolve is a lookup and a digest
/// over a fixed preimage, so what crosses the boundary is the whole of
/// what varies.
///
/// # Errors
///
/// A deterministic refusal (a handle that names no write, or a cell
/// holding something that is not a seal).
pub fn open_seal<P: HostAccess + FuelSink>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<Drawn, MeterError> {
    let drawn = refused(port.host().open_seal(site, element))?;
    charge(port, SEED_BYTES)?;
    Ok(drawn)
}

/// `crypto.hash`.
pub fn hash<P: HostAccess + FuelSink>(port: &mut P, data: &[u8]) -> Result<[u8; 32], MeterError> {
    let digest = port.host().hash(data);
    charge(port, data.len() + digest.len())?;
    Ok(digest)
}

/// `events.emit`.
pub fn emit<P: HostAccess + FuelSink>(
    port: &mut P,
    event_type: u32,
    payload: Vec<u8>,
) -> Result<(), MeterError> {
    charge(port, payload.len())?;
    refused(port.host().emit(event_type, payload))
}
