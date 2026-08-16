//! The non-fungible guest: instances as holdings entries. `mint` writes
//! one instance's data cell and produces its one-id edge, `deposit` files
//! arriving ids as entries at their ids, `withdraw` removes named ids —
//! trapping on one not held — and `burn` consumes an edge outright.

wit_bindgen::generate!({
    path: ["../../crates/sdk/wit/deps/kernel", "wit"],
    world: "test:guest/nf",
    generate_all,
});

use hyperscale::kernel::state::{
    Amount, range_write_count, range_write_insert, range_write_order, range_write_remove,
    write_cell_set,
};

/// A `u128` as the kernel's world names it.
#[allow(clippy::cast_possible_truncation)] // taking a half is the truncation
const fn amount(value: u128) -> Amount {
    Amount {
        low: value as u64,
        high: (value >> 64) as u64,
    }
}

/// The `u128` an `amount` carries.
const fn whole(value: Amount) -> u128 {
    (value.low as u128) | ((value.high as u128) << 64)
}

/// The ids a count-prefixed edge cell carries; traps on any other shape.
fn cell_ids(cell: &[u8]) -> Vec<u64> {
    let (&count, ids) = cell.split_first().expect("an id cell has a count");
    assert!(ids.len() == usize::from(count) * 8, "malformed id cell");
    ids.chunks_exact(8)
        .map(|id| u64::from_le_bytes(id.try_into().unwrap()))
        .collect()
}

/// An id's position in the holdings interval's order-key space.
const fn order_of(id: u64) -> Amount {
    amount(id as u128)
}

struct Nf;

impl Guest for Nf {
    fn mint(data: &WriteCell, id: u64) -> Vec<u8> {
        write_cell_set(data, &id.to_le_bytes());
        let mut cell = vec![1u8];
        cell.extend_from_slice(&id.to_le_bytes());
        cell
    }

    fn deposit(holdings: &RangeWrite, funds: Vec<u8>) {
        for id in cell_ids(&funds) {
            range_write_insert(holdings, order_of(id), &[1]);
        }
    }

    fn withdraw(holdings: &RangeWrite, ids: Vec<u8>) -> Vec<u8> {
        for id in cell_ids(&ids) {
            let order = u128::from(id);
            let held = (0..range_write_count(holdings))
                .find(|&index| whole(range_write_order(holdings, index)) == order)
                .expect("id not held");
            range_write_remove(holdings, held);
        }
        ids
    }

    fn burn(funds: Vec<u8>) {
        let _ = cell_ids(&funds);
    }

    fn operate() {
        // The gate is the kernel's; a body would have nothing to say.
    }
}

export!(Nf);
