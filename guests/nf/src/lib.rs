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
    burn, instance_range_put, instance_range_take, mint_instances, write_cell_set,
};

struct Nf;

impl Guest for Nf {
    fn mint(data: &WriteCell, id: u64, i: &Issuer) -> Bucket {
        write_cell_set(data, &id.to_le_bytes());
        mint_instances(i, &[id])
    }

    fn deposit(holdings: &InstanceRange, funds: Bucket) {
        instance_range_put(holdings, funds, &[1]);
    }

    fn withdraw(holdings: &InstanceRange, ids: Vec<u64>) -> Bucket {
        instance_range_take(holdings, &ids)
    }

    fn burn(funds: Bucket, i: &Issuer) {
        burn(i, funds);
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
