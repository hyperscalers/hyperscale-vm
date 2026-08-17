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
//!
//! The range functions charge a second supplement, for what materializing
//! an interval lifted out of the store — bytes that never cross the ABI
//! and so are invisible to the first. Charged whether the call then
//! succeeds or refuses, because the page was read either way.

use core::cmp::Ordering;

use hyperscale_vm_embed::KernelHost;
use hyperscale_vm_embed::math::{self, Rounding, U256};
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

/// What a wide word costs at the boundary: the width it has.
const WIDE_BOUNDARY_BYTES: usize = 32;

/// The `math` interface's `wide`: a 256-bit word as four limbs, least
/// significant first.
///
/// Flat rather than a pair of [`Amount`]s, because the profile admits a
/// record whose every field is a scalar — the property that makes it
/// flatten into registers — and a record of records is outside it.
#[derive(Clone, Copy, ComponentType, Lift, Lower)]
#[component(record)]
pub struct Wide {
    /// Bits 0 to 63.
    pub limb0: u64,
    /// Bits 64 to 127.
    pub limb1: u64,
    /// Bits 128 to 191.
    pub limb2: u64,
    /// Bits 192 to 255.
    pub limb3: u64,
}

impl From<U256> for Wide {
    fn from(value: U256) -> Self {
        let [limb0, limb1, limb2, limb3] = value.limbs();
        Self {
            limb0,
            limb1,
            limb2,
            limb3,
        }
    }
}

impl From<Wide> for U256 {
    fn from(value: Wide) -> Self {
        Self::from_limbs([value.limb0, value.limb1, value.limb2, value.limb3])
    }
}

/// The `math` interface's `rounding`.
#[derive(Clone, Copy, ComponentType, Lift, Lower)]
#[component(enum)]
#[repr(u8)]
pub enum WitRounding {
    /// Toward zero.
    #[component(name = "down")]
    Down,
    /// Away from zero.
    #[component(name = "up")]
    Up,
}

impl From<WitRounding> for Rounding {
    fn from(value: WitRounding) -> Self {
        match value {
            WitRounding::Down => Self::Down,
            WitRounding::Up => Self::Up,
        }
    }
}

/// The `math` interface's `ordering`.
#[derive(Clone, Copy, ComponentType, Lift, Lower)]
#[component(enum)]
#[repr(u8)]
pub enum WitOrdering {
    /// The first is smaller.
    #[component(name = "less")]
    Less,
    /// The two are equal.
    #[component(name = "equal")]
    Equal,
    /// The first is larger.
    #[component(name = "greater")]
    Greater,
}

impl From<Ordering> for WitOrdering {
    fn from(value: Ordering) -> Self {
        match value {
            Ordering::Less => Self::Less,
            Ordering::Equal => Self::Equal,
            Ordering::Greater => Self::Greater,
        }
    }
}

/// Host-side marker for the `bucket` resource.
///
/// The one resource in the world a guest owns rather than borrows, so
/// the one whose handle table entry the guest can discard — which is why
/// it is the only one whose destructor does anything.
pub struct Bucket;
/// Host-side marker for the `issuer` resource.
pub struct Issuer;
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

/// Charges what the call just made lifted out of the store by scanning.
///
/// Every range function asks, because every one of them can reach a
/// scan — and the session refuses to finish still owing, so one that
/// stopped asking fails rather than executing for free.
///
/// Asked before the call's own refusal propagates, because the page was
/// read either way: an index the scan does not contain is a refusal the
/// scan had to happen to reach.
fn charge_scan<T: KernelHost>(store: &mut StoreContextMut<'_, T>) -> Result<()> {
    let lifted = store.data_mut().take_scan_debt();
    charge_boundary_bytes(store, lifted)
}

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
    state.resource("issuer", ResourceType::host::<Issuer>(), |_, _| Ok(()))?;
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
    // A take charges its amount argument and nothing for the handle it
    // yields: a bucket crosses as a table index, where the amount it
    // carries never crosses at all.
    state.func_wrap(
        "issuer-take",
        |mut store: StoreContextMut<'_, T>, (i, amount): (Resource<Issuer>, Amount)| {
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            let rep = store
                .data_mut()
                .issuer_take(i.rep(), amount.into())
                .map_err(host_trap)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "write-cell-take",
        |mut store: StoreContextMut<'_, T>, (r, amount): (Resource<WriteCell>, Amount)| {
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            let rep = store
                .data_mut()
                .write_take(r.rep(), amount.into())
                .map_err(host_trap)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    // A put consumes the handle the guest passed: the canonical ABI
    // lifts an owned argument out of the caller's table, so the rep
    // arrives here and the guest no longer has it.
    state.func_wrap(
        "issuer-put",
        |mut store: StoreContextMut<'_, T>, (i, funds): (Resource<Issuer>, Resource<Bucket>)| {
            store
                .data_mut()
                .issuer_put(i.rep(), funds.rep())
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "issuer-mint",
        |mut store: StoreContextMut<'_, T>, (i, ids): (Resource<Issuer>, Vec<u8>)| {
            charge_boundary_bytes(&mut store, ids.len())?;
            let rep = store
                .data_mut()
                .issuer_mint(i.rep(), &ids)
                .map_err(host_trap)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "range-write-take",
        |mut store: StoreContextMut<'_, T>, (r, ids): (Resource<RangeWrite>, Vec<u8>)| {
            charge_boundary_bytes(&mut store, ids.len())?;
            let taken = store.data_mut().range_take(r.rep(), &ids);
            charge_scan(&mut store)?;
            Ok((Resource::<Bucket>::new_own(taken.map_err(host_trap)?),))
        },
    )?;
    state.func_wrap(
        "range-write-put",
        |mut store: StoreContextMut<'_, T>,
         (r, funds, value): (Resource<RangeWrite>, Resource<Bucket>, Vec<u8>)| {
            charge_boundary_bytes(&mut store, value.len())?;
            store
                .data_mut()
                .range_put(r.rep(), funds.rep(), value)
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "bucket-take",
        |mut store: StoreContextMut<'_, T>, (b, amount): (Resource<Bucket>, Amount)| {
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            let rep = store
                .data_mut()
                .bucket_take(b.rep(), amount.into())
                .map_err(host_trap)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "bucket-split",
        |mut store: StoreContextMut<'_, T>, (b, num, den): (Resource<Bucket>, Wide, Wide)| {
            charge_boundary_bytes(&mut store, WIDE_BOUNDARY_BYTES * 2)?;
            let rep = store
                .data_mut()
                .bucket_split(b.rep(), num.into(), den.into())
                .map_err(host_trap)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "bucket-put",
        |mut store: StoreContextMut<'_, T>, (b, other): (Resource<Bucket>, Resource<Bucket>)| {
            store
                .data_mut()
                .bucket_put(b.rep(), other.rep())
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "bucket-amount",
        |mut store: StoreContextMut<'_, T>, (b,): (Resource<Bucket>,)| {
            let amount = store.data_mut().bucket_amount(b.rep()).map_err(host_trap)?;
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            Ok((Amount::from(amount),))
        },
    )?;
    state.func_wrap(
        "write-cell-put",
        |mut store: StoreContextMut<'_, T>, (r, funds): (Resource<WriteCell>, Resource<Bucket>)| {
            store
                .data_mut()
                .write_put(r.rep(), funds.rep())
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "delta-cell-put",
        |mut store: StoreContextMut<'_, T>, (r, funds): (Resource<DeltaCell>, Resource<Bucket>)| {
            store
                .data_mut()
                .delta_put(r.rep(), funds.rep())
                .map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "delta-cell-take",
        |mut store: StoreContextMut<'_, T>, (r, amount): (Resource<DeltaCell>, Amount)| {
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            let rep = store
                .data_mut()
                .delta_take(r.rep(), amount.into())
                .map_err(host_trap)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "reserve-cell-take",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<ReserveCell>,)| {
            let rep = store.data_mut().reserve_take(r.rep()).map_err(host_trap)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;

    state.func_wrap(
        "range-read-count",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<RangeRead>,)| {
            let count = store.data_mut().range_count(r.rep());
            charge_scan(&mut store)?;
            Ok((count.map_err(host_trap)?,))
        },
    )?;
    state.func_wrap(
        "range-read-order",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeRead>, u32)| {
            let order = store.data_mut().range_order(r.rep(), index);
            charge_scan(&mut store)?;
            let order = order.map_err(host_trap)?;
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            Ok((Amount::from(order),))
        },
    )?;
    state.func_wrap(
        "range-read-entry",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeRead>, u32)| {
            let value = store.data_mut().range_entry(r.rep(), index);
            charge_scan(&mut store)?;
            let value = value.map_err(host_trap)?;
            charge_boundary_bytes(&mut store, value.len())?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "range-write-count",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<RangeWrite>,)| {
            let count = store.data_mut().range_count(r.rep());
            charge_scan(&mut store)?;
            Ok((count.map_err(host_trap)?,))
        },
    )?;
    state.func_wrap(
        "range-write-order",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeWrite>, u32)| {
            let order = store.data_mut().range_order(r.rep(), index);
            charge_scan(&mut store)?;
            let order = order.map_err(host_trap)?;
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES)?;
            Ok((Amount::from(order),))
        },
    )?;
    state.func_wrap(
        "range-write-entry",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeWrite>, u32)| {
            let value = store.data_mut().range_entry(r.rep(), index);
            charge_scan(&mut store)?;
            let value = value.map_err(host_trap)?;
            charge_boundary_bytes(&mut store, value.len())?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "range-write-set",
        |mut store: StoreContextMut<'_, T>,
         (r, index, value): (Resource<RangeWrite>, u32, Vec<u8>)| {
            charge_boundary_bytes(&mut store, value.len())?;
            let set = store.data_mut().range_set(r.rep(), index, value);
            charge_scan(&mut store)?;
            set.map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "range-write-insert",
        |mut store: StoreContextMut<'_, T>,
         (r, order, value): (Resource<RangeWrite>, Amount, Vec<u8>)| {
            charge_boundary_bytes(&mut store, AMOUNT_BOUNDARY_BYTES + value.len())?;
            let inserted = store.data_mut().range_insert(r.rep(), order.into(), value);
            charge_scan(&mut store)?;
            inserted.map_err(host_trap)
        },
    )?;
    state.func_wrap(
        "range-write-remove",
        |mut store: StoreContextMut<'_, T>, (r, index): (Resource<RangeWrite>, u32)| {
            let removed = store.data_mut().range_remove(r.rep(), index);
            charge_scan(&mut store)?;
            removed.map_err(host_trap)
        },
    )?;

    // Wide arithmetic reaches no state and asks the host nothing, so
    // these call the shared functions rather than a trait the embedder
    // could answer differently. What the engine contributes is the
    // charge: the operands and the result cross, and both engines price
    // them at the width they have.
    let mut wide_math = linker.instance("hyperscale:kernel/math")?;
    wide_math.func_wrap(
        "mul-div",
        |mut store: StoreContextMut<'_, T>, (a, b, c, r): (Wide, Wide, Wide, WitRounding)| {
            charge_boundary_bytes(&mut store, WIDE_BOUNDARY_BYTES * 4)?;
            let product = math::mul_div(a.into(), b.into(), c.into(), r.into())
                .map_err(|error| host_trap(error.into()))?;
            Ok((Wide::from(product),))
        },
    )?;
    wide_math.func_wrap(
        "geometric-mean",
        |mut store: StoreContextMut<'_, T>, (a, b): (Wide, Wide)| {
            charge_boundary_bytes(&mut store, WIDE_BOUNDARY_BYTES * 3)?;
            Ok((Wide::from(math::geometric_mean(a.into(), b.into())),))
        },
    )?;
    wide_math.func_wrap(
        "fraction-compose",
        |mut store: StoreContextMut<'_, T>, (an, ad, bn, bd): (Wide, Wide, Wide, Wide)| {
            charge_boundary_bytes(&mut store, WIDE_BOUNDARY_BYTES * 6)?;
            let (num, den) = math::fraction_compose(an.into(), ad.into(), bn.into(), bd.into())
                .map_err(|error| host_trap(error.into()))?;
            Ok(((Wide::from(num), Wide::from(den)),))
        },
    )?;
    wide_math.func_wrap(
        "fraction-cmp",
        |mut store: StoreContextMut<'_, T>, (an, ad, bn, bd): (Wide, Wide, Wide, Wide)| {
            charge_boundary_bytes(&mut store, WIDE_BOUNDARY_BYTES * 4)?;
            let order = math::fraction_cmp(an.into(), ad.into(), bn.into(), bd.into())
                .map_err(|error| host_trap(error.into()))?;
            Ok((WitOrdering::from(order),))
        },
    )?;
    wide_math.func_wrap(
        "fixed-pow",
        |mut store: StoreContextMut<'_, T>, (base, exp, r): (Wide, u32, WitRounding)| {
            charge_boundary_bytes(&mut store, WIDE_BOUNDARY_BYTES * 2)?;
            let raised = math::fixed_pow(base.into(), exp, r.into())
                .map_err(|error| host_trap(error.into()))?;
            Ok((Wide::from(raised),))
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
