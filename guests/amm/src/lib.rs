//! The constant-product pool guest: real read-modify-write over the two
//! reserve cells, fee from the locked configuration snapshot, checked
//! arithmetic throughout — any overflow is a deterministic trap.

wit_bindgen::generate!({
    path: "wit",
    world: "amm",
    generate_all,
});

use hyperscale::kernel::state::{snap_cell_get, write_cell_get, write_cell_set};

fn amount(bytes: &[u8]) -> u128 {
    bytes.try_into().map_or(0, u128::from_le_bytes)
}

struct Amm;

impl Guest for Amm {
    fn swap(
        config: &SnapCell,
        reserve_in: &WriteCell,
        reserve_out: &WriteCell,
        input: Vec<u8>,
        min_out: Vec<u8>,
    ) -> Vec<u8> {
        let raw = snap_cell_get(config);
        let fee_bps = u64::from(u16::from_le_bytes(raw[..2].try_into().unwrap()));
        let x = amount(&write_cell_get(reserve_in));
        let y = amount(&write_cell_get(reserve_out));
        let dx = amount(&input);

        let dx_effective = dx
            .checked_mul(u128::from(10_000 - fee_bps))
            .unwrap()
            / 10_000;
        let out = y
            .checked_mul(dx_effective)
            .unwrap()
            / x.checked_add(dx_effective).unwrap();
        assert!(out >= amount(&min_out), "output below the declared floor");

        write_cell_set(reserve_in, &(x + dx).to_le_bytes());
        write_cell_set(reserve_out, &(y - out).to_le_bytes());
        out.to_le_bytes().to_vec()
    }
}

export!(Amm);
