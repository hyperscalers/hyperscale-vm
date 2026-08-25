//! The non-fungible guest: instances as holdings entries. `mint` writes
//! one instance's data cell and issues it, `deposit` files an arriving
//! edge's instances, `withdraw` takes named ones out — trapping on one
//! not held — and `burn` destroys them under the same grant that made
//! them.

wit_bindgen::generate!({
    path: ["../../crates/sdk/wit/deps/kernel", "wit"],
    world: "test:guest/nf",
    generate_all,
});

use hyperscale::kernel::state::{
    capability_instance_put, capability_instance_take, capability_set, burn, mint_instances,
};

struct Nf;

impl Guest for Nf {
    fn mint(data: &Capability, id: u64) -> Bucket {
        capability_set(data, &id.to_le_bytes());
        mint_instances(&[id])
    }

    fn deposit(holdings: &Capability, funds: Bucket) {
        capability_instance_put(holdings, funds, &[1]);
    }

    fn withdraw(holdings: &Capability, ids: Vec<u64>) -> Bucket {
        capability_instance_take(holdings, &ids)
    }

    fn burn(funds: Bucket) {
        burn(funds);
    }

    fn operate() {
        // The gate is the kernel's; a body would have nothing to say.
    }

    fn operate_instance() {
        // Likewise: what differs is which claim the gate names, which is
        // the declaration's business and never this body's.
    }

    fn operate_quorum() {
        // Likewise again: a threshold is a shape the declaration holds,
        // so counting the presentations is the kernel's and not this
        // body's either.
    }
}

export!(Nf);
