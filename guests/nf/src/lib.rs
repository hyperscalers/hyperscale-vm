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
    mint_instances, burn, range_write_put, range_write_take, write_cell_set,
};

/// One id in the framing a declared id list crosses in: a count byte,
/// then that many little-endian `u64`s.
fn one_id(id: u64) -> Vec<u8> {
    let mut cell = vec![1u8];
    cell.extend_from_slice(&id.to_le_bytes());
    cell
}

struct Nf;

impl Guest for Nf {
    fn mint(data: &WriteCell, id: u64, i: &Issuer) -> Bucket {
        write_cell_set(data, &id.to_le_bytes());
        mint_instances(i, &one_id(id))
    }

    fn deposit(holdings: &RangeWrite, funds: Bucket) {
        range_write_put(holdings, funds, &[1]);
    }

    fn withdraw(holdings: &RangeWrite, ids: Vec<u8>) -> Bucket {
        range_write_take(holdings, &ids)
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
