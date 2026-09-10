//! The counter, as the blessed engine reaches it.
//!
//! The meter's pass defines the counter inside the module and exports it
//! as `fuel`; the engine's part is small. It answers `exhaust` with the
//! out-of-gas refusal, sets the counter before a call and reads it after,
//! charges boundary bytes into it, and prepays instantiation off the
//! bytes — the one piece of work that runs before the counter exists.

use hyperscale_vm_meter::{EXHAUST, FUEL, NAMESPACE};
use hyperscale_vm_types::AbortReason;
use wasmtime::{AsContextMut, Caller, Error, Extern, Global, Instance, Linker, Result, Store, Val};

use crate::abort::host_trap;

/// The counter an admitted module exports.
///
/// # Panics
///
/// Panics if the instance exports none: the module was not admitted
/// through the meter, which is an embedder's wiring defect and never an
/// input-dependent condition.
pub fn counter(store: impl AsContextMut, instance: &Instance) -> Global {
    instance
        .get_global(store, FUEL)
        .expect("an admitted module exports the meter's counter")
}

/// What the counter holds.
pub fn remaining(store: impl AsContextMut, counter: &Global) -> u64 {
    match counter.get(store) {
        Val::I64(held) => held.cast_unsigned(),
        other => unreachable!("the meter's counter is an i64, not {other:?}"),
    }
}

/// Set the counter.
///
/// # Panics
///
/// Panics if the counter refuses the write, which the meter's mutable
/// `i64` never does.
pub fn set(store: impl AsContextMut, counter: &Global, value: u64) {
    counter
        .set(store, Val::I64(value.cast_signed()))
        .expect("the meter's counter is mutable");
}

/// Exhaust the counter: nothing left, and the refusal that says so.
///
/// One site for both ways of running out — a block the module cannot
/// pay for, which reaches here through `exhaust`, and a boundary charge
/// the counter cannot cover — so a receipt reads the whole budget as
/// spent either way.
pub(crate) fn exhausted(store: impl AsContextMut, counter: &Global) -> Error {
    set(store, counter, 0);
    host_trap(AbortReason::OutOfGas)
}

/// Adds the meter's one import to a linker: `exhaust`, which the pass
/// calls where a block's charge exceeds what the counter holds.
///
/// # Errors
///
/// Fails only on a duplicate definition in the linker — a wiring
/// defect, never an input-dependent condition.
///
/// # Panics
///
/// The import panics when called from an instance exporting no
/// counter, which no admitted module is.
pub fn add_meter_import<T: 'static>(linker: &mut Linker<T>) -> Result<()> {
    linker.func_wrap(
        NAMESPACE,
        EXHAUST,
        |mut caller: Caller<'_, T>| -> Result<()> {
            let counter = caller
                .get_export(FUEL)
                .and_then(Extern::into_global)
                .expect("an admitted module exports the meter's counter");
            Err(exhausted(&mut caller, &counter))
        },
    )?;
    Ok(())
}

/// Instantiate under `budget`, prepaying `cost` — what
/// [`instantiation_cost`](hyperscale_vm_meter::instantiation_cost)
/// derived from the same bytes — and leaving the counter holding the
/// rest for the call that follows.
///
/// Refused before any instantiation work happens where the budget does
/// not cover the prepayment: the counter does not exist until the module
/// does, so this is the one charge the host judges itself.
///
/// # Errors
///
/// The out-of-gas refusal where `budget` is under `cost`; otherwise
/// whatever `instantiate` itself returns.
pub fn instantiate_metered<T>(
    store: &mut Store<T>,
    budget: u64,
    cost: u64,
    instantiate: impl FnOnce(&mut Store<T>) -> Result<Instance>,
) -> Result<Instance> {
    let Some(left) = budget.checked_sub(cost) else {
        return Err(host_trap(AbortReason::OutOfGas));
    };
    let instance = instantiate(store)?;
    let counter = counter(&mut *store, &instance);
    set(&mut *store, &counter, left);
    Ok(instance)
}
