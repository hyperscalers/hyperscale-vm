//! The minimal stdlib account: reservation-backed withdrawal, delta
//! deposit. Feasibility is judged before execution, so `withdraw` only
//! checks that the granted reservation is the amount the manifest asked
//! for.

wit_bindgen::generate!({
    path: "wit",
    world: "account",
    generate_all,
});

use hyperscale::kernel::state::{delta_cell_add, reserve_cell_amount};

struct Account;

impl Guest for Account {
    fn withdraw(vault: &ReserveCell, amount: Vec<u8>) -> Vec<u8> {
        let reserved = reserve_cell_amount(vault);
        assert!(reserved == amount, "reservation does not match the request");
        reserved
    }

    fn deposit(vault: &DeltaCell, amount: Vec<u8>) {
        delta_cell_add(vault, &amount);
    }
}

export!(Account);
