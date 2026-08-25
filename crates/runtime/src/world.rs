//! The `hyperscale:kernel` world, host side.
//!
//! [`add_kernel_to_linker`] wires the world's four interfaces — `state`,
//! `env`, `crypto`, `events` — against a [`KernelHost`] implementation.
//! The state interface carries two resources; the kernel lends sites per
//! transaction ([`wasmtime::component::Resource`] values whose rep
//! indexes the host's own site table), and the world has no constructor
//! for one, so the declared set is the reachable set. Which operations a
//! site admits is not in its type: the kernel holds the capability at
//! that element to the operation, and refuses there.
//!
//! Every function crossing bytes charges the boundary supplement against
//! the store's fuel. The cost model — prices, per-function byte counts,
//! and the order charges interleave with host operations — lives once in
//! [`hyperscale_vm_embed::meter`], shared with the reference interpreter;
//! [`crate::gas::Port`] adapts the store to it. A host operation's
//! refusal (a bad amount cell, an out-of-bounds entry index) is a
//! deterministic trap carrying the host's own abort class.

use core::cmp::Ordering;

use hyperscale_vm_embed::KernelHost;
use hyperscale_vm_embed::meter::{self, MeterError};
use hyperscale_vm_types::math::{Rounding, U256};
use hyperscale_vm_types::{AbortReason, Drawn};
use wasmtime::component::{ComponentType, Lift, Linker, Lower, Resource, ResourceType};
use wasmtime::{Error, Result, StoreContextMut, Trap};

use crate::gas::Port;

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

/// The `state` interface's `word`: a protocol word as four limbs, least
/// significant first.
///
/// Flat for the reason [`Amount`] is: the width is the protocol's, and a
/// boundary that carried it as a byte list would put the length in a
/// convention instead of in the type.
#[derive(Clone, Copy, ComponentType, Lift, Lower)]
#[component(record)]
pub struct WitWord {
    /// Bytes 0 to 7.
    pub limb0: u64,
    /// Bytes 8 to 15.
    pub limb1: u64,
    /// Bytes 16 to 23.
    pub limb2: u64,
    /// Bytes 24 to 31.
    pub limb3: u64,
}

impl From<[u8; 32]> for WitWord {
    fn from(bytes: [u8; 32]) -> Self {
        let limb = |i: usize| {
            let mut eight = [0u8; 8];
            eight.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            u64::from_le_bytes(eight)
        };
        Self {
            limb0: limb(0),
            limb1: limb(1),
            limb2: limb(2),
            limb3: limb(3),
        }
    }
}

/// The `state` interface's `drawn`.
#[derive(Clone, Copy, ComponentType, Lift, Lower)]
#[component(variant)]
pub enum WitDrawn {
    /// The epoch the seal matures into is not folded yet.
    #[component(name = "pending")]
    Pending,
    /// The word the seal committed to.
    #[component(name = "ready")]
    Ready(WitWord),
    /// The seal will never open.
    #[component(name = "expired")]
    Expired,
}

impl From<Drawn> for WitDrawn {
    fn from(drawn: Drawn) -> Self {
        match drawn {
            Drawn::Pending => Self::Pending,
            Drawn::Ready(word) => Self::Ready(word.into()),
            Drawn::Expired => Self::Expired,
        }
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
/// Host-side marker for the `site` resource.
///
/// One marker for every mode and every width: a handle type says which
/// table its rep indexes, and every site indexes the one the walk bound.
pub struct Site;

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

/// A metered failure as an engine error: exhaustion as the engine's own
/// trap, a kernel refusal with its class recoverable.
fn fault(error: MeterError) -> Error {
    match error {
        MeterError::Exhausted => Trap::OutOfFuel.into(),
        MeterError::Refused(reason) => host_trap(reason),
    }
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
    state.resource("site", ResourceType::host::<Site>(), |_, _| Ok(()))?;

    state.func_wrap(
        "site-get",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            let value = meter::site_get(&mut Port(&mut store), r.rep(), element).map_err(fault)?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "site-set",
        |mut store: StoreContextMut<'_, T>, (r, element, value): (Resource<Site>, u32, Vec<u8>)| {
            meter::site_set(&mut Port(&mut store), r.rep(), element, value).map_err(fault)
        },
    )?;
    state.func_wrap(
        "site-seal",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            meter::site_seal(&mut Port(&mut store), r.rep(), element).map_err(fault)
        },
    )?;
    state.func_wrap(
        "site-open-seal",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            let drawn =
                meter::site_open_seal(&mut Port(&mut store), r.rep(), element).map_err(fault)?;
            Ok((WitDrawn::from(drawn),))
        },
    )?;
    state.func_wrap(
        "site-clear",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            meter::site_clear(&mut Port(&mut store), r.rep(), element).map_err(fault)
        },
    )?;
    state.func_wrap(
        "site-balance",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            let held =
                meter::site_balance(&mut Port(&mut store), r.rep(), element).map_err(fault)?;
            Ok((Amount::from(held),))
        },
    )?;
    state.func_wrap(
        "site-take",
        |mut store: StoreContextMut<'_, T>, (r, element, amount): (Resource<Site>, u32, Amount)| {
            let rep = meter::site_take(&mut Port(&mut store), r.rep(), element, amount.into())
                .map_err(fault)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "site-put",
        |mut store: StoreContextMut<'_, T>,
         (r, element, funds): (Resource<Site>, u32, Resource<Bucket>)| {
            meter::site_put(&mut Port(&mut store), r.rep(), element, funds.rep()).map_err(fault)
        },
    )?;
    state.func_wrap(
        "site-reserve-take",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            let rep =
                meter::site_reserve_take(&mut Port(&mut store), r.rep(), element).map_err(fault)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "site-count",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            Ok((meter::site_count(&mut Port(&mut store), r.rep(), element).map_err(fault)?,))
        },
    )?;
    state.func_wrap(
        "site-covered",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            Ok((meter::site_covered(&mut Port(&mut store), r.rep(), element).map_err(fault)?,))
        },
    )?;
    state.func_wrap(
        "site-order",
        |mut store: StoreContextMut<'_, T>, (r, element, index): (Resource<Site>, u32, u32)| {
            let order =
                meter::site_order(&mut Port(&mut store), r.rep(), element, index).map_err(fault)?;
            Ok((Amount::from(order),))
        },
    )?;
    state.func_wrap(
        "site-entry",
        |mut store: StoreContextMut<'_, T>, (r, element, index): (Resource<Site>, u32, u32)| {
            let value =
                meter::site_entry(&mut Port(&mut store), r.rep(), element, index).map_err(fault)?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "site-entry-set",
        |mut store: StoreContextMut<'_, T>,
         (r, element, index, value): (Resource<Site>, u32, u32, Vec<u8>)| {
            meter::site_entry_set(&mut Port(&mut store), r.rep(), element, index, value)
                .map_err(fault)
        },
    )?;
    state.func_wrap(
        "site-insert",
        |mut store: StoreContextMut<'_, T>,
         (r, element, order, value): (Resource<Site>, u32, Amount, Vec<u8>)| {
            meter::site_insert(&mut Port(&mut store), r.rep(), element, order.into(), value)
                .map_err(fault)
        },
    )?;
    state.func_wrap(
        "site-remove",
        |mut store: StoreContextMut<'_, T>, (r, element, index): (Resource<Site>, u32, u32)| {
            meter::site_remove(&mut Port(&mut store), r.rep(), element, index).map_err(fault)
        },
    )?;
    state.func_wrap(
        "site-instance-take",
        |mut store: StoreContextMut<'_, T>, (r, element, ids): (Resource<Site>, u32, Vec<u64>)| {
            let rep = meter::site_instance_take(&mut Port(&mut store), r.rep(), element, &ids)
                .map_err(fault)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "site-instance-put",
        |mut store: StoreContextMut<'_, T>,
         (r, element, funds, value): (Resource<Site>, u32, Resource<Bucket>, Vec<u8>)| {
            meter::site_instance_put(&mut Port(&mut store), r.rep(), element, funds.rep(), value)
                .map_err(fault)
        },
    )?;
    state.func_wrap(
        "mint",
        |mut store: StoreContextMut<'_, T>, (amount,): (Amount,)| {
            let rep = meter::mint(&mut Port(&mut store), amount.into()).map_err(fault)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "burn",
        |mut store: StoreContextMut<'_, T>, (funds,): (Resource<Bucket>,)| {
            meter::burn(&mut Port(&mut store), funds.rep()).map_err(fault)
        },
    )?;
    state.func_wrap(
        "mint-instances",
        |mut store: StoreContextMut<'_, T>, (ids,): (Vec<u64>,)| {
            let rep = meter::mint_instances(&mut Port(&mut store), &ids).map_err(fault)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "bucket-take",
        |mut store: StoreContextMut<'_, T>, (b, amount): (Resource<Bucket>, Amount)| {
            let rep =
                meter::bucket_take(&mut Port(&mut store), b.rep(), amount.into()).map_err(fault)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "bucket-split",
        |mut store: StoreContextMut<'_, T>, (b, num, den): (Resource<Bucket>, Wide, Wide)| {
            let rep = meter::bucket_split(&mut Port(&mut store), b.rep(), num.into(), den.into())
                .map_err(fault)?;
            Ok((Resource::<Bucket>::new_own(rep),))
        },
    )?;
    state.func_wrap(
        "bucket-put",
        |mut store: StoreContextMut<'_, T>, (b, other): (Resource<Bucket>, Resource<Bucket>)| {
            meter::bucket_put(&mut Port(&mut store), b.rep(), other.rep()).map_err(fault)
        },
    )?;
    state.func_wrap(
        "bucket-amount",
        |mut store: StoreContextMut<'_, T>, (b,): (Resource<Bucket>,)| {
            let amount = meter::bucket_amount(&mut Port(&mut store), b.rep()).map_err(fault)?;
            Ok((Amount::from(amount),))
        },
    )?;
    state.func_wrap(
        "site-len",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<Site>,)| {
            Ok((meter::site_len(&mut Port(&mut store), r.rep()).map_err(fault)?,))
        },
    )?;
    state.func_wrap(
        "site-declared",
        |mut store: StoreContextMut<'_, T>, (r, element): (Resource<Site>, u32)| {
            let declared =
                meter::site_declared(&mut Port(&mut store), r.rep(), element).map_err(fault)?;
            Ok((declared,))
        },
    )?;

    // Wide arithmetic reaches no state and asks the host nothing: the
    // meter calls the shared functions and prices the crossing, so the
    // engine contributes only the lift and the lower.
    let mut wide_math = linker.instance("hyperscale:kernel/math")?;
    wide_math.func_wrap(
        "mul-div",
        |mut store: StoreContextMut<'_, T>, (a, b, c, r): (Wide, Wide, Wide, WitRounding)| {
            let product = meter::mul_div(
                &mut Port(&mut store),
                a.into(),
                b.into(),
                c.into(),
                r.into(),
            )
            .map_err(fault)?;
            Ok((Wide::from(product),))
        },
    )?;
    wide_math.func_wrap(
        "geometric-mean",
        |mut store: StoreContextMut<'_, T>, (a, b): (Wide, Wide)| {
            let mean =
                meter::geometric_mean(&mut Port(&mut store), a.into(), b.into()).map_err(fault)?;
            Ok((Wide::from(mean),))
        },
    )?;
    wide_math.func_wrap(
        "fraction-compose",
        |mut store: StoreContextMut<'_, T>, (an, ad, bn, bd): (Wide, Wide, Wide, Wide)| {
            let (num, den) = meter::fraction_compose(
                &mut Port(&mut store),
                an.into(),
                ad.into(),
                bn.into(),
                bd.into(),
            )
            .map_err(fault)?;
            Ok(((Wide::from(num), Wide::from(den)),))
        },
    )?;
    wide_math.func_wrap(
        "fraction-cmp",
        |mut store: StoreContextMut<'_, T>, (an, ad, bn, bd): (Wide, Wide, Wide, Wide)| {
            let order = meter::fraction_cmp(
                &mut Port(&mut store),
                an.into(),
                ad.into(),
                bn.into(),
                bd.into(),
            )
            .map_err(fault)?;
            Ok((WitOrdering::from(order),))
        },
    )?;
    wide_math.func_wrap(
        "fixed-pow",
        |mut store: StoreContextMut<'_, T>, (base, exp, r): (Wide, u32, WitRounding)| {
            let raised = meter::fixed_pow(&mut Port(&mut store), base.into(), exp, r.into())
                .map_err(fault)?;
            Ok((Wide::from(raised),))
        },
    )?;

    let mut env = linker.instance("hyperscale:kernel/env")?;
    env.func_wrap("clock", |store: StoreContextMut<'_, T>, (): ()| {
        Ok((store.data().clock_ms(),))
    })?;

    let mut crypto = linker.instance("hyperscale:kernel/crypto")?;
    crypto.func_wrap(
        "hash",
        |mut store: StoreContextMut<'_, T>, (data,): (Vec<u8>,)| {
            let digest = meter::hash(&mut Port(&mut store), &data).map_err(fault)?;
            Ok((digest.to_vec(),))
        },
    )?;

    let mut events = linker.instance("hyperscale:kernel/events")?;
    events.func_wrap(
        "emit",
        |mut store: StoreContextMut<'_, T>, (event_type, payload): (u32, Vec<u8>)| {
            meter::emit(&mut Port(&mut store), event_type, payload).map_err(fault)
        },
    )?;

    Ok(())
}
