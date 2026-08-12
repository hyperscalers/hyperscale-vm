//! The minimal stdlib account: reservation-backed withdrawal, delta
//! deposit, and the entropy stamp. Feasibility is judged before
//! execution, so `withdraw` only checks that the granted reservation is
//! the amount the manifest asked for.

wit_bindgen::generate!({
    path: "wit",
    world: "account",
    generate_all,
});

use hyperscale::kernel::env::randomness;
use hyperscale::kernel::events::emit;
use hyperscale::kernel::state::{
    delta_cell_add, reserve_cell_amount, write_cell_set,
};

struct Account;

/// The account's event table: the indexes a consumer resolves against
/// this package's metadata.
const WITHDRAWN: u32 = 0;
const DEPOSITED: u32 = 1;

impl Guest for Account {
    fn withdraw(vault: &ReserveCell, amount: Vec<u8>) -> Vec<u8> {
        let reserved = reserve_cell_amount(vault);
        assert!(reserved == amount, "reservation does not match the request");
        emit(WITHDRAWN, &reserved);
        reserved
    }

    fn deposit(vault: &DeltaCell, amount: Vec<u8>) {
        delta_cell_add(vault, &amount);
        emit(DEPOSITED, &amount);
    }

    fn stamp_entropy(leaf: &WriteCell) {
        write_cell_set(leaf, &randomness());
    }

    fn authorize() {
        // The gate is the kernel's; a body would have nothing to say.
    }
}

export!(Account);
