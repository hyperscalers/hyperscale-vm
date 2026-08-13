//! The non-fungible guest: instances as holdings entries. `mint` writes
//! one instance's data cell and produces its one-id edge, `deposit` files
//! arriving ids as entries at their ids, `withdraw` removes named ids —
//! trapping on one not held — and `burn` consumes an edge outright.

wit_bindgen::generate!({
    path: "wit",
    world: "nf",
    generate_all,
});

use hyperscale::kernel::state::{
    range_write_count, range_write_insert, range_write_order, range_write_remove, write_cell_set,
};

/// The ids a count-prefixed edge cell carries; traps on any other shape.
fn cell_ids(cell: &[u8]) -> Vec<u64> {
    let (&count, ids) = cell.split_first().expect("an id cell has a count");
    assert!(ids.len() == usize::from(count) * 8, "malformed id cell");
    ids.chunks_exact(8)
        .map(|id| u64::from_le_bytes(id.try_into().unwrap()))
        .collect()
}

/// An id's position in the holdings interval's order-key space.
fn order_cell(id: u64) -> [u8; 16] {
    u128::from(id).to_le_bytes()
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
            range_write_insert(holdings, &order_cell(id), &[1]);
        }
    }

    fn withdraw(holdings: &RangeWrite, ids: Vec<u8>) -> Vec<u8> {
        for id in cell_ids(&ids) {
            let order = order_cell(id);
            let held = (0..range_write_count(holdings))
                .find(|&index| range_write_order(holdings, index) == order)
                .expect("id not held");
            range_write_remove(holdings, held);
        }
        ids
    }

    fn burn(funds: Vec<u8>) {
        let _ = cell_ids(&funds);
    }
}

export!(Nf);
