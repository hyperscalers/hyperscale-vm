//! The minimal stdlib account: reservation-backed withdrawal and delta
//! deposit. Feasibility is judged before
//! execution, so `withdraw` only checks that the granted reservation is
//! the amount the manifest asked for.
//!
//! The stored-authority cell is a frame this guest splices without a
//! codec: `[u32 LE base_len][base]`, optionally followed by
//! `[u64 LE effective_at_ms][base']` running to the cell's end, where
//! `base = [u64 LE recovery_delay_ms][role-set bytes]`. The role-set
//! bytes are opaque here — admission validated them, the kernel's gate
//! decodes them — so every operation below is concatenation, integer
//! reads at fixed offsets, and one saturating add.

wit_bindgen::generate!({
    path: "wit",
    world: "account",
    generate_all,
});

use hyperscale::kernel::env::clock;
use hyperscale::kernel::events::emit;
use hyperscale::kernel::state::{
    delta_cell_add, range_write_count, range_write_insert, range_write_order, range_write_remove,
    reserve_cell_amount, write_cell_get, write_cell_set,
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

struct Account;

/// The account's event table: the indexes a consumer resolves against
/// this package's metadata.
const WITHDRAWN: u32 = 0;
const DEPOSITED: u32 = 1;

/// One base's frame bytes: the delay, then the opaque role set.
fn base(roles: &[u8], delay_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + roles.len());
    out.extend_from_slice(&delay_ms.to_le_bytes());
    out.extend_from_slice(roles);
    out
}

/// One whole cell from its parts.
fn frame(base: &[u8], proposal: Option<(u64, &[u8])>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + base.len());
    out.extend_from_slice(&u32::try_from(base.len()).unwrap().to_le_bytes());
    out.extend_from_slice(base);
    if let Some((effective_at_ms, proposed)) = proposal {
        out.extend_from_slice(&effective_at_ms.to_le_bytes());
        out.extend_from_slice(proposed);
    }
    out
}

/// A stored cell split into its base and, if present, its proposal.
/// Only this guest writes the cell, so a frame that does not split is
/// unreachable and the indexing panic is the trap it deserves.
fn split(cell: &[u8]) -> (&[u8], Option<(u64, &[u8])>) {
    let base_len = u32::from_le_bytes(cell[0..4].try_into().unwrap()) as usize;
    let base = &cell[4..4 + base_len];
    let tail = &cell[4 + base_len..];
    let proposal = if tail.is_empty() {
        None
    } else {
        let effective_at_ms = u64::from_le_bytes(tail[0..8].try_into().unwrap());
        Some((effective_at_ms, &tail[8..]))
    };
    (base, proposal)
}

/// The base that governs now: the proposal's once its instant has
/// arrived, the stored one until then. The write-side twin of the
/// gate's own comparison — promoting here is compaction of what reads
/// already answer, never a change of verdict.
fn governing(cell: &[u8]) -> &[u8] {
    let (base, proposal) = split(cell);
    match proposal {
        Some((effective_at_ms, proposed)) if effective_at_ms <= clock() => proposed,
        _ => base,
    }
}

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

    fn authorize() {
        // The gate is the kernel's; a body would have nothing to say.
    }

    fn deposit_nf(holdings: &RangeWrite, funds: Vec<u8>) {
        for id in cell_ids(&funds) {
            range_write_insert(holdings, &order_cell(id), &[1]);
        }
    }

    fn withdraw_nf(holdings: &RangeWrite, ids: Vec<u8>) -> Vec<u8> {
        for id in cell_ids(&ids) {
            let order = order_cell(id);
            let held = (0..range_write_count(holdings))
                .find(|&index| range_write_order(holdings, index) == order)
                .expect("id not held");
            range_write_remove(holdings, held);
        }
        ids
    }

    fn present_badge() {
        // The gate is the kernel's, possession included; a body would
        // have nothing to say.
    }

    fn securify(cell: &WriteCell, roles: Vec<u8>, delay_ms: u64) {
        // The admission gate decoded the roles under the vocabulary
        // caps; what is left to judge here is the one-way door.
        assert!(
            write_cell_get(cell).is_empty(),
            "the account is already securified"
        );
        write_cell_set(cell, &frame(&base(&roles, delay_ms), None));
    }

    fn propose(cell: &WriteCell, roles: Vec<u8>, delay_ms: u64) {
        let stored = write_cell_get(cell);
        assert!(!stored.is_empty(), "the account is not securified");
        // The wait comes from the delay that governs now, never from
        // the proposer: the proposal's own delay only starts governing
        // when the proposal does.
        let current = governing(&stored);
        let wait = u64::from_le_bytes(current[0..8].try_into().unwrap());
        let effective_at_ms = clock().saturating_add(wait);
        write_cell_set(
            cell,
            &frame(current, Some((effective_at_ms, &base(&roles, delay_ms)))),
        );
    }

    fn cancel(cell: &WriteCell) {
        let stored = write_cell_get(cell);
        assert!(!stored.is_empty(), "the account is not securified");
        // A matured proposal is promoted, not cancelled: it already
        // governs, and this write only compacts that fact.
        write_cell_set(cell, &frame(governing(&stored), None));
    }

    fn confirm(cell: &WriteCell) {
        let stored = write_cell_get(cell);
        assert!(!stored.is_empty(), "the account is not securified");
        let (_, proposal) = split(&stored);
        let (_, proposed) = proposal.expect("nothing is pending");
        write_cell_set(cell, &frame(proposed, None));
    }
}

export!(Account);
