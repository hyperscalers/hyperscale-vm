//! The metering layer: engine fuel plus the canonical-ABI copy supplement.
//!
//! Engine fuel meters guest instructions but is blind to boundary copies — a
//! value crossing the canonical ABI moves bytes with host memcpys the fuel
//! schedule never sees. Every kernel-world host function therefore charges
//! [`charge_boundary_bytes`] for the bytes it lifts and lowers, deducted from
//! the same fuel budget so one number governs the transaction.

use wasmtime::{Result, StoreContextMut, Trap};

/// Fuel units charged per byte crossing the canonical ABI boundary.
pub const FUEL_PER_BOUNDARY_BYTE: u64 = 1;

/// Deducts the boundary charge for `bytes` from the store's fuel.
///
/// # Errors
///
/// Fails with [`Trap::OutOfFuel`] when the budget cannot cover the charge —
/// fuel is set to zero first, matching the engine's own exhaustion behavior —
/// or if the store has fuel metering disabled.
pub fn charge_boundary_bytes<T>(store: &mut StoreContextMut<'_, T>, bytes: usize) -> Result<()> {
    let cost = (bytes as u64).saturating_mul(FUEL_PER_BOUNDARY_BYTE);
    let fuel = store.get_fuel()?;
    if let Some(remaining) = fuel.checked_sub(cost) {
        store.set_fuel(remaining)?;
        Ok(())
    } else {
        store.set_fuel(0)?;
        Err(Trap::OutOfFuel.into())
    }
}
