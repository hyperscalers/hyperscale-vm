//! The `hyperscale:kernel` world, host side.
//!
//! [`add_kernel_to_linker`] wires the world's four interfaces — `state`,
//! `env`, `crypto`, `events` — against a [`KernelHost`] implementation. The
//! state interface carries one resource per access mode; the kernel materializes
//! handles per transaction ([`wasmtime::component::Resource`] values whose
//! rep indexes the host's declared-set table), and the world has no handle
//! constructor, so the declared set is the reachable set and an undeclared
//! *mode* is as inexpressible as an undeclared key — the canonical ABI
//! rejects a wrong-typed handle before any host code runs.
//!
//! Every function crossing bytes charges the [`crate::gas`] boundary
//! supplement against the store's fuel: argument bytes before the host
//! operation, result bytes after it succeeds. A host operation's refusal
//! (a bad amount cell, an out-of-bounds entry index) is a deterministic
//! trap carrying the host's own abort class.

use hyperscale_vm_types::AbortReason;
use wasmtime::component::{ComponentType, Lift, Linker, Lower, Resource, ResourceType};
use wasmtime::{Error, Result, StoreContextMut};

use crate::gas::charge_boundary_bytes;

/// What an amount costs at the boundary.
///
/// The width it has, not the width it travels in: a flat record copies
/// nothing through linear memory, and pricing it at zero would make a
/// movement's fee turn on the encoding rather than on the value crossing.
/// Both engines charge this, which is what keeps the figure agreed.
const AMOUNT_BOUNDARY_BYTES: usize = 16;

/// The world's `amount`: a `u128` as the two halves the component model
/// can name.
///
/// A record rather than a byte list, so it flattens across the boundary
/// instead of travelling through linear memory — which is what leaves a
/// guest that moves an amount with no allocation to make, and what makes
/// a malformed amount inexpressible from a guest rather than refused by
/// the kernel.
#[derive(Clone, Copy, ComponentType, Lift, Lower)]
#[component(record)]
pub struct Amount {
    /// The low 64 bits.
    pub low: u64,
    /// The high 64 bits.
    pub high: u64,
}

impl From<u128> for Amount {
    #[allow(clippy::cast_possible_truncation)] // taking a half is the truncation
    fn from(value: u128) -> Self {
        Self {
            low: value as u64,
            high: (value >> 64) as u64,
        }
    }
}

impl From<Amount> for u128 {
    fn from(value: Amount) -> Self {
        Self::from(value.low) | (Self::from(value.high) << 64)
    }
}

/// Host-side marker for the `bucket` resource.
///
/// The one resource in the world a guest owns rather than borrows, so
/// the one whose handle table entry the guest can discard — which is why
/// it is the only one whose destructor does anything.
pub struct Bucket;
/// Host-side marker for the `read-cell` resource.
pub struct ReadCell;
/// Host-side marker for the `locked-cell` resource.
pub struct LockedCell;
/// Host-side marker for the `write-cell` resource.
pub struct WriteCell;
/// Host-side marker for the `delta-cell` resource.
pub struct DeltaCell;
/// Host-side marker for the `reserve-cell` resource.
pub struct ReserveCell;
/// Host-side marker for the `range-read` resource.
pub struct RangeRead;
/// Host-side marker for the `range-write` resource.
pub struct RangeWrite;

/// The kernel's host surface behind the world.
///
/// Implementations hold per-transaction state: the materialized capability
/// table, the transaction clock, the randomness draw, and the emission
/// buffer a completed outcome turns into receipt events. Reps are indexes
/// the host itself assigned when materializing handles, so lookups are
/// infallible by construction; fallible operations return a deterministic
/// [`AbortReason`] that becomes the receipt's abort class on every
/// replica. The host classifies; the boundary transports.
pub trait KernelHost: Send {
    /// The cell's current bytes; empty if absent.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;

    /// The cell's pinned bytes; empty if absent.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn locked_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;

    /// The cell's current bytes under a write capability; empty if absent.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;

    /// Replace the cell's bytes.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), AbortReason>;

    /// Credit the amount cell.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn delta_add(&mut self, rep: u32, amount: u128) -> Result<(), AbortReason>;

    /// Debit the amount cell unconditionally.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn delta_sub(&mut self, rep: u32, amount: u128) -> Result<(), AbortReason>;

    /// The reserved amount this transaction holds.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn reserve_amount(&mut self, rep: u32) -> Result<u128, AbortReason>;

    /// Entries currently in the interval, bounded by the declared cap.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn range_count(&mut self, rep: u32) -> Result<u32, AbortReason>;

    /// The order key of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn range_order(&mut self, rep: u32, index: u32) -> Result<u128, AbortReason>;

    /// The value of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, AbortReason>;

    /// Replace the value of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), AbortReason>;

    /// Insert or replace the entry at `order` within the declared interval.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (an order outside the interval).
    fn range_insert(&mut self, rep: u32, order: u128, value: Vec<u8>) -> Result<(), AbortReason>;

    /// Remove the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), AbortReason>;

    /// The transaction clock in milliseconds.
    fn clock_ms(&self) -> u64;

    /// The transaction's randomness draw.
    fn randomness(&self) -> [u8; 32];

    /// The protocol hash function.
    fn hash(&self, data: &[u8]) -> [u8; 32];

    /// A bucket handle the guest let go of.
    ///
    /// The canonical ABI routes a discarded owned handle here and the
    /// host decides what it means. Delivery is the property an owned
    /// handle has and a value type cannot be given: a record can carry an
    /// amount, and it cannot notice being forgotten.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason>;

    /// Emit an event from the executing instance; the host stamps the
    /// emitter.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (a cap or the event-type ceiling).
    fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), AbortReason>;
}

/// A host refusal as an engine trap, with its class recoverable.
///
/// The class rides the error rather than its text: the backend downcasts
/// it back out, so nothing on the path from the kernel's verdict to the
/// receipt's abort record passes through prose.
fn host_trap(reason: AbortReason) -> Error {
    Error::new(HostRefusal(reason))
}

/// A kernel refusal in flight through the engine.
#[derive(Debug, thiserror::Error)]
#[error("kernel refusal: {0:?}")]
pub struct HostRefusal(pub AbortReason);

/// Adds the `hyperscale:kernel` interfaces to a component linker.
///
/// # Errors
///
/// Fails only on duplicate definitions in the linker — a wiring defect, never
/// an input-dependent condition.
#[allow(clippy::too_many_lines)] // one registration block per world function
pub fn add_kernel_to_linker<T: KernelHost + 'static>(linker: &mut Linker<T>) -> Result<()> {
    let mut state = linker.instance("hyperscale:kernel/state")?;
    // The one destructor with a body. A guest owns its buckets, so
    // dropping one is a thing it can do and a thing the host is told
    // about; every cell arrives as a borrow the ABI takes back at scope
    // exit, and there is nothing for the host to decide.
    state.resource(
        "bucket",
        ResourceType::host::<Bucket>(),
        |mut store: StoreContextMut<'_, T>, rep| {
            store.data_mut().bucket_drop(rep).map_err(host_trap)
        },
    )?;
    state.resource("read-cell", ResourceType::host::<ReadCell>(), |_, _| Ok(()))?;
    state.resource("locked-cell", ResourceType::host::<LockedCell>(), |_, _| {
        Ok(())
    })?;
    state.resource("write-cell", ResourceType::host::<WriteCell>(), |_, _| {
        Ok(())
    })?;
    state.resource("delta-cell", ResourceType::host::<DeltaCell>(), |_, _| {
        Ok(())
    })?;
    state.resource(
        "reserve-cell",
        ResourceType::host::<ReserveCell>(),
        |_, _| Ok(()),
    )?;
    state.resource("range-read", ResourceType::host::<RangeRead>(), |_, _| {
        Ok(())
    })?;
    state.resource("range-write", ResourceType::host::<RangeWrite>(), |_, _| {
        Ok(())
    })?;

    state.func_wrap(
        "read-cell-get",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<ReadCell>,)| {
            let value = store.data_mut().read_cell(r.rep()).map_err(host_trap)?;
            charge_boundary_bytes(&mut store, value.len())?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "locked-cell-get",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<LockedCell>,)| {
            let value = store.data_mut().locked_cell(r.rep()).map_err(host_trap)?;
            charge_boundary_bytes(&mut store, value.len())?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "write-cell-get",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<WriteCell>,)| {
            let value = store
                .data_mut()
                .write_cell_get(r.rep())
                .map_err(host_trap)?;
            charge_boundary_bytes(&mut store, value.len())?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "write-cell-set",
        |mut store: StoreContextMut<'_, T>, (r, value): (Resource<WriteCell>, Vec<u8>)| {
            charge_boundary_bytes(&mut store, value.len())?;
            store
                .data_mut()
                .write_cell_set(r.rep(), value)
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "delta-cell-add",
        |mut store: StoreContextMut<'_, T>, (r, amount): (Resource<DeltaCell>, Amount)| {
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            store
                .data_mut()
                .delta_add(r.rep(), amount.into())
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "delta-cell-sub",
        |mut store: StoreContextMut<'_, T>, (r, amount): (Resource<DeltaCell>, Amount)| {
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            store
                .data_mut()
                .delta_sub(r.rep(), amount.into())
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "reserve-cell-amount",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<ReserveCell>,)| {
            let amount = store
                .data_mut()
                .reserve_amount(r.rep())
                .map_err(host_trap)?;
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            Ok((Amount::from(amount),))
        },
    )?;

    state.func_wrap(
        "range-read-count",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<RangeRead>,)| {
            Ok((store.data_mut().range_count(r.rep()).map_err(host_trap)?,))
        },
    )?;
    state.func_wrap(
        "range-read-order",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeRead>, u32)| {
            let order = store
                .data_mut()
                .range_order(r.rep(), index)
                .map_err(host_trap)?;
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            Ok((Amount::from(order),))
        },
    )?;
    state.func_wrap(
        "range-read-entry",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeRead>, u32)| {
            let value = store
                .data_mut()
                .range_entry(r.rep(), index)
                .map_err(host_trap)?;
            charge_boundary_bytes(&mut store, value.len())?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "range-write-count",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<RangeWrite>,)| {
            Ok((store.data_mut().range_count(r.rep()).map_err(host_trap)?,))
        },
    )?;
    state.func_wrap(
        "range-write-order",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeWrite>, u32)| {
            let order = store
                .data_mut()
                .range_order(r.rep(), index)
                .map_err(host_trap)?;
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            Ok((Amount::from(order),))
        },
    )?;
    state.func_wrap(
        "range-write-entry",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeWrite>, u32)| {
            let value = store
                .data_mut()
                .range_entry(r.rep(), index)
                .map_err(host_trap)?;
            charge_boundary_bytes(&mut store, value.len())?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "range-write-set",
        |mut store: StoreContextMut<'_, T>,
         (r, index, value): (Resource<RangeWrite>, u32, Vec<u8>)| {
            charge_boundary_bytes(&mut store, value.len())?;
            store
                .data_mut()
                .range_set(r.rep(), index, value)
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "range-write-insert",
        |mut store: StoreContextMut<'_, T>,
         (r, order, value): (Resource<RangeWrite>, Amount, Vec<u8>)| {
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES + value.len())?;
            store
                .data_mut()
                .range_insert(r.rep(), order.into(), value)
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "range-write-remove",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeWrite>, u32)| {
            store
                .data_mut()
                .range_remove(r.rep(), index)
                .map_err(host_trap)
        },
    )?;

    let mut env = linker.instance("hyperscale:kernel/env")?;
    env.func_wrap("clock", |store: StoreContextMut<'_, T>, (): ()| {
        Ok((store.data().clock_ms(),))
    })?;
    env.func_wrap("randomness", |mut store: StoreContextMut<'_, T>, (): ()| {
        let draw = store.data().randomness();
        charge_boundary_bytes(&mut store, draw.len())?;
        Ok((draw.to_vec(),))
    })?;

    let mut crypto = linker.instance("hyperscale:kernel/crypto")?;
    crypto.func_wrap(
        "hash",
        |mut store: StoreContextMut<'_, T>, (data,): (Vec<u8>,)| {
            let digest = store.data().hash(&data);
            charge_boundary_bytes(&mut store, data.len() + digest.len())?;
            Ok((digest.to_vec(),))
        },
    )?;

    let mut events = linker.instance("hyperscale:kernel/events")?;
    events.func_wrap(
        "emit",
        |mut store: StoreContextMut<'_, T>, (event_type, payload): (u32, Vec<u8>)| {
            charge_boundary_bytes(&mut store, payload.len())?;
            store
                .data_mut()
                .emit(event_type, payload)
                .map_err(host_trap)
        },
    )?;

    Ok(())
}
