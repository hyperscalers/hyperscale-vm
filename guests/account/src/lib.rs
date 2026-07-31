//! The minimal stdlib account: reservation-backed withdrawal, delta
//! deposit, a pinned balance guard, and the entropy stamp. Feasibility is
//! judged before execution, so `withdraw` only checks that the granted
//! reservation is the amount the manifest asked for.

wit_bindgen::generate!({
    path: "wit",
    world: "account",
    generate_all,
});

use hyperscale::kernel::env::randomness;
use hyperscale::kernel::state::{
    delta_cell_add, reserve_cell_amount, snap_cell_get, write_cell_set,
};

struct Account;

fn amount_of(cell: &[u8]) -> u128 {
    if cell.is_empty() {
        return 0;
    }
    u128::from_le_bytes(cell.try_into().expect("amount cells are 16 bytes"))
}

impl Guest for Account {
    fn withdraw(vault: &ReserveCell, amount: Vec<u8>) -> Vec<u8> {
        let reserved = reserve_cell_amount(vault);
        assert!(reserved == amount, "reservation does not match the request");
        reserved
    }

    fn deposit(vault: &DeltaCell, amount: Vec<u8>) {
        delta_cell_add(vault, &amount);
    }

    fn assert_balance(vault: &SnapCell, min: Vec<u8>) {
        assert!(
            amount_of(&snap_cell_get(vault)) >= amount_of(&min),
            "pinned balance below the required minimum"
        );
    }

    fn stamp_entropy(leaf: &WriteCell) {
        write_cell_set(leaf, &randomness());
    }
}

export!(Account);
