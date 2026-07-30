//! The realistic guest fixture: a balance transfer over the kernel world,
//! built with the pinned wit-bindgen toolchain.
//!
//! Feasibility is judged before execution — the reservation this guest
//! holds is already granted — so the guest's own check is the application
//! floor (`min`), whose violation is a deterministic trap.

wit_bindgen::generate!({
    path: "wit",
    world: "transfer",
    generate_all,
});

use hyperscale::kernel::crypto::hash;
use hyperscale::kernel::env::{clock, randomness};
use hyperscale::kernel::state::{delta_cell_add, reserve_cell_amount};

fn amount(bytes: &[u8]) -> u128 {
    bytes.try_into().map_or(0, u128::from_le_bytes)
}

struct Transfer;

impl Guest for Transfer {
    fn run(sender: &ReserveCell, recipient: &DeltaCell, min: u64) -> u64 {
        let cell = reserve_cell_amount(sender);
        let reserved = amount(&cell);
        assert!(reserved >= u128::from(min), "reserved amount below floor");
        delta_cell_add(recipient, &cell);

        let digest = hash(&randomness());
        clock()
            .wrapping_add(u64::try_from(reserved).unwrap_or(u64::MAX))
            .wrapping_add(u64::from(digest[0]))
    }
}

export!(Transfer);
