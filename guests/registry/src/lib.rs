//! The registry guest: bindings in an unordered collection. `bind` writes
//! the entry at its hashed order, `check` traps on a missing or
//! mismatched binding, and `drain` removes the declared tail's entries.

wit_bindgen::generate!({
    path: ["../../crates/sdk/wit/deps/kernel", "wit"],
    world: "test:guest/registry",
    generate_all,
});

use hyperscale::kernel::state::{Amount, site_count, site_entry, site_insert, site_remove};

/// A `u128` as the kernel's world names it.
#[allow(clippy::cast_possible_truncation)] // taking a half is the truncation
const fn amount(value: u128) -> Amount {
    Amount {
        low: value as u64,
        high: (value >> 64) as u64,
    }
}

/// The order an entry cell names. The binding hands this guest the
/// kernel's own cell, so an off-width one never arrives and reads zero.
fn order_of(cell: &[u8]) -> Amount {
    amount(cell.try_into().map_or(0, u128::from_le_bytes))
}

struct Registry;

impl Guest for Registry {
    fn bind(entry: &Site, order: Vec<u8>, value: Vec<u8>) {
        site_insert(entry, 0, order_of(&order), &value);
    }

    fn check(entry: &Site, expected: Vec<u8>) {
        assert!(site_count(entry, 0) == 1, "unbound name");
        assert!(site_entry(entry, 0, 0) == expected, "mismatched binding");
    }

    fn drain(tail: &Site) {
        while site_count(tail, 0) > 0 {
            site_remove(tail, 0, 0);
        }
    }
}

export!(Registry);
