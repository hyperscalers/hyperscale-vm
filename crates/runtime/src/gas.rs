//! The engine's side of the metering seam.
//!
//! The cost model — constants, per-function byte formulas, and the order
//! charges interleave with host operations — lives in
//! [`hyperscale_vm_embed::meter`], shared with the reference interpreter.
//! What this module contributes is the adapter: the wasmtime store as the
//! meter's two capabilities, its data the host and its fuel the sink, so
//! boundary debt lands in the same counter the engine's own instruction
//! checks read.

use hyperscale_vm_embed::KernelHost;
use hyperscale_vm_embed::meter::{Exhausted, FuelSink, HostAccess};
use wasmtime::StoreContextMut;

/// The store, seen as what the meter needs.
pub struct Port<'a, 'b, T: 'static>(pub &'a mut StoreContextMut<'b, T>);

impl<T: KernelHost + 'static> HostAccess for Port<'_, '_, T> {
    type Host = T;

    fn host(&mut self) -> &mut T {
        self.0.data_mut()
    }
}

impl<T: 'static> FuelSink for Port<'_, '_, T> {
    fn consume(&mut self, fuel: u64) -> Result<(), Exhausted> {
        let current = self.0.get_fuel().expect("fuel metering is enabled");
        if let Some(remaining) = current.checked_sub(fuel) {
            self.0
                .set_fuel(remaining)
                .expect("fuel metering is enabled");
            Ok(())
        } else {
            // Zeroed first, matching the engine's own exhaustion behavior.
            self.0.set_fuel(0).expect("fuel metering is enabled");
            Err(Exhausted)
        }
    }
}
