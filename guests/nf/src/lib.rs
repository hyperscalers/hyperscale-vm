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
    burn, mint_instances, site_instance_put, site_instance_take, site_set,
};

struct Nf;

impl Guest for Nf {
    fn mint(data: &Site, id: u64) -> Bucket {
        site_set(data, 0, &id.to_le_bytes());
        // The one issuance this method declares, so index zero — the
        // hand-authored twin of what the lowering computes for a body
        // that writes the mark instead.
        mint_instances(0, &[id])
    }

    fn deposit(holdings: &Site, funds: Bucket) {
        site_instance_put(holdings, 0, funds, &[1]);
    }

    fn withdraw(holdings: &Site, ids: Vec<u64>) -> Bucket {
        site_instance_take(holdings, 0, &ids)
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
