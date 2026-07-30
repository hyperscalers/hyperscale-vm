//! The realistic guest fixture: a balance transfer over the kernel world,
//! built with the pinned wit-bindgen toolchain.

wit_bindgen::generate!({
    path: "wit",
    world: "transfer",
    generate_all,
});

use hyperscale::kernel::crypto::hash;
use hyperscale::kernel::env::{clock, randomness};
use hyperscale::kernel::state::{read, write};

fn balance(bytes: &[u8]) -> u64 {
    bytes.try_into().map_or(0, u64::from_le_bytes)
}

struct Transfer;

impl Guest for Transfer {
    fn run(a: &Substate, b: &Substate, amount: u64) -> u64 {
        let from = balance(&read(a));
        let to = balance(&read(b));
        assert!(from >= amount, "insufficient balance");
        write(a, &(from - amount).to_le_bytes());
        write(b, &(to + amount).to_le_bytes());

        let digest = hash(&randomness());
        clock()
            .wrapping_add(to + amount)
            .wrapping_add(u64::from(digest[0]))
    }
}

export!(Transfer);
