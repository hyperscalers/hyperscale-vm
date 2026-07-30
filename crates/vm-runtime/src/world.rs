//! The `hyperscale:kernel` world, host side.
//!
//! [`add_kernel_to_linker`] wires the world's three interfaces — `state`,
//! `env`, `crypto` — against a [`KernelHost`] implementation. The kernel
//! materializes substate handles per transaction ([`wasmtime::component::Resource`]
//! values whose rep indexes the host's declared-set table); the world itself
//! has no handle constructor, so the declared set is the reachable set.
//!
//! Every function crossing bytes charges the [`crate::gas`] boundary
//! supplement against the store's fuel.

use wasmtime::component::{Linker, Resource, ResourceType};
use wasmtime::{Result, StoreContextMut};

use crate::gas::charge_boundary_bytes;

/// Host-side marker for the `substate` resource. The kernel mints handles
/// with [`Resource::new_borrow`] over reps indexing its per-transaction
/// declared-set table.
pub struct Substate;

/// The kernel's host surface behind the world.
///
/// Implementations hold per-transaction state: the declared substates, the
/// transaction clock, and the randomness draw. Reps are indexes the host
/// itself assigned when materializing handles, so lookups are infallible by
/// construction.
pub trait KernelHost: Send {
    /// The substate's current bytes; empty if absent.
    fn read(&mut self, rep: u32) -> Vec<u8>;

    /// Replace the substate's bytes.
    fn write(&mut self, rep: u32, value: Vec<u8>);

    /// The transaction clock in milliseconds.
    fn clock_ms(&self) -> u64;

    /// The transaction's randomness draw.
    fn randomness(&self) -> [u8; 32];

    /// The protocol hash function.
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

/// Adds the `hyperscale:kernel` interfaces to a component linker.
///
/// # Errors
///
/// Fails only on duplicate definitions in the linker — a wiring defect, never
/// an input-dependent condition.
pub fn add_kernel_to_linker<T: KernelHost + 'static>(linker: &mut Linker<T>) -> Result<()> {
    let mut state = linker.instance("hyperscale:kernel/state")?;
    state.resource("substate", ResourceType::host::<Substate>(), |_, _| Ok(()))?;
    state.func_wrap(
        "read",
        |mut store: StoreContextMut<'_, T>, (r,): (Resource<Substate>,)| {
            let value = store.data_mut().read(r.rep());
            charge_boundary_bytes(&mut store, value.len())?;
            Ok((value,))
        },
    )?;
    state.func_wrap(
        "write",
        |mut store: StoreContextMut<'_, T>, (r, value): (Resource<Substate>, Vec<u8>)| {
            charge_boundary_bytes(&mut store, value.len())?;
            store.data_mut().write(r.rep(), value);
            Ok(())
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

    Ok(())
}
