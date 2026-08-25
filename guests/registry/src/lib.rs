//! The registry guest: bindings in an unordered collection. `bind` writes
//! the entry at its hashed order, `check` traps on a missing or
//! mismatched binding, and `drain` removes the declared tail's entries.

wit_bindgen::generate!({
    path: ["../../crates/sdk/wit/deps/kernel", "wit"],
    world: "test:guest/registry",
    generate_all,
});

use hyperscale::kernel::state::{
    Amount, capability_count, capability_entry, capability_insert, capability_remove,
};

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
    fn bind(entry: &Capability, order: Vec<u8>, value: Vec<u8>) {
        capability_insert(entry, order_of(&order), &value);
    }

    fn check(entry: &Capability, expected: Vec<u8>) {
        assert!(capability_count(entry) == 1, "unbound name");
        assert!(
            capability_entry(entry, 0) == expected,
            "mismatched binding"
        );
    }

    fn drain(tail: &Capability) {
        while capability_count(tail) > 0 {
            capability_remove(tail, 0);
        }
    }
}

export!(Registry);
