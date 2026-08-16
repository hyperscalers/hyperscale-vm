//! The registry guest: bindings in an unordered collection. `bind` writes
//! the entry at its hashed order, `check` traps on a missing or
//! mismatched binding, and `drain` removes the declared tail's entries.

wit_bindgen::generate!({
    path: ["../../crates/sdk/wit/deps/kernel", "wit"],
    world: "test:guest/registry",
    generate_all,
});

use hyperscale::kernel::state::{
    range_read_count, range_read_entry, range_write_count, range_write_insert, range_write_remove,
};

struct Registry;

impl Guest for Registry {
    fn bind(entry: &RangeWrite, order: Vec<u8>, value: Vec<u8>) {
        range_write_insert(entry, &order, &value);
    }

    fn check(entry: &RangeRead, expected: Vec<u8>) {
        assert!(range_read_count(entry) == 1, "unbound name");
        assert!(
            range_read_entry(entry, 0) == expected,
            "mismatched binding"
        );
    }

    fn drain(tail: &RangeWrite) {
        while range_write_count(tail) > 0 {
            range_write_remove(tail, 0);
        }
    }
}

export!(Registry);
