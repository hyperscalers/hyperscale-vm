//! The order-book guest: placement inserts at `price | seq` inside the
//! declared interval; filling walks the interval's best price first,
//! consuming and partially rewriting entries, and settles both escrow
//! vaults by delta. Checked arithmetic throughout — overflow is a
//! deterministic trap.

wit_bindgen::generate!({
    path: ["../../crates/sdk/wit/deps/kernel", "wit"],
    world: "test:guest/book",
    generate_all,
});

use hyperscale::kernel::state::{
    delta_cell_add, delta_cell_sub, range_write_count, range_write_entry, range_write_insert,
    range_write_order, range_write_remove, range_write_set,
};

fn amount(bytes: &[u8]) -> u128 {
    bytes.try_into().map_or(0, u128::from_le_bytes)
}

struct Book;

impl Guest for Book {
    fn place_ask(asks: &RangeWrite, escrow: &DeltaCell, price: u64, seq: u64, amount_cell: Vec<u8>) {
        let order = (u128::from(price) << 64) | u128::from(seq);
        range_write_insert(asks, &order.to_le_bytes(), &amount_cell);
        delta_cell_add(escrow, &amount_cell);
    }

    fn fill_asks(
        asks: &RangeWrite,
        base_escrow: &DeltaCell,
        quote_escrow: &DeltaCell,
        budget_cell: Vec<u8>,
    ) -> Vec<u8> {
        let opening = amount(&budget_cell);
        let mut budget = opening;
        let mut bought: u128 = 0;
        while range_write_count(asks) > 0 {
            let order = amount(&range_write_order(asks, 0));
            let price = order >> 64;
            assert!(price > 0, "zero-priced ask");
            let available = amount(&range_write_entry(asks, 0));
            let affordable = budget / price;
            let take = available.min(affordable);
            if take == 0 {
                break;
            }
            let cost = take.checked_mul(price).unwrap();
            budget -= cost;
            bought = bought.checked_add(take).unwrap();
            if take == available {
                range_write_remove(asks, 0);
            } else {
                range_write_set(asks, 0, &(available - take).to_le_bytes());
            }
        }
        let spent = opening - budget;
        delta_cell_sub(base_escrow, &bought.to_le_bytes());
        delta_cell_add(quote_escrow, &spent.to_le_bytes());

        let mut result = bought.to_le_bytes().to_vec();
        result.extend(budget.to_le_bytes());
        result
    }
}

export!(Book);
