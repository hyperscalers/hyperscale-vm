//! The realistic guest fixture: a balance transfer over the kernel world,
//! written against the SDK's state vocabulary rather than against the raw
//! imports.
//!
//! What the SDK supplies here is the half a contract shares with every
//! other contract: the kernel bindings, generated once and reached
//! through this package's own world, and the handle types the accessors
//! hang off. What stays this package's own is its world and its body —
//! the macro that would generate both is a later step, and its absence is
//! what makes this a proof that the vocabulary carries a real guest.
//!
//! Feasibility is judged before execution — the reservation this guest
//! holds is already granted — so the guest's own check is the application
//! floor (`min`), whose violation is a deterministic trap.

wit_bindgen::generate!({
    path: ["../../crates/sdk/wit/deps/kernel", "wit"],
    world: "test:guest/transfer",
    // The kernel interfaces are bound in the SDK, once. Generating them
    // again here would produce a second set of Rust types for the same
    // resources, and the SDK's accessors could not be called with them.
    with: {
        "hyperscale:kernel/state": hyperscale_vm_sdk::guest::kernel::state,
        "hyperscale:kernel/env": hyperscale_vm_sdk::guest::kernel::env,
        "hyperscale:kernel/crypto": hyperscale_vm_sdk::guest::kernel::crypto,
    },
});

use hyperscale_vm_sdk::guest::{Handle, clock_ms, hash, randomness};
use hyperscale_vm_sdk::state::{Amount, Slot};

struct Transfer;

impl Guest for Transfer {
    fn run(sender: &ReserveCell, recipient: &DeltaCell, min: u64) -> u64 {
        // The handles the kernel materialized, named by the mode each
        // was declared under. Generated code writes this; here it is
        // written out, which is the point of the fixture.
        // The grant is the bucket, so the floor is checked against the
        // value in hand rather than against a reading of it, and the same
        // value is what moves.
        let mut sender = Slot::<Amount>::at(Handle::Reserve(sender.handle()));
        let funds = sender.reserve(0);
        let reserved = funds.amount();
        assert!(reserved >= u128::from(min), "reserved amount below floor");

        let mut recipient = Slot::<Amount>::at(Handle::Delta(recipient.handle()));
        recipient.put(funds);

        let digest = hash(&randomness());
        clock_ms()
            .wrapping_add(u64::try_from(reserved).unwrap_or(u64::MAX))
            .wrapping_add(u64::from(digest[0]))
    }
}

export!(Transfer);
