//! The lottery guest: entries into a pot, and a winner chosen by the
//! transaction's randomness draw.
//!
//! The draw is the only thing here that could not be written some other
//! way. A winner picked from the clock, the entrant count, or any value a
//! signer supplies is a winner somebody could have arranged; the kernel's
//! randomness is fixed by the block that committed the transaction, so
//! the first moment anyone learns it is after the round is closed.
//!
//! The result cell records the draw beside the winner. A lottery that
//! publishes only its winner asks to be trusted about how it got one —
//! publishing the draw lets a reader check it against the block that
//! fixed it, and lets two shards settling one transaction be compared
//! against each other.
//!
//! Entrants are the tickets collection rather than a list in a cell, so
//! two people entering at once commute: each writes its own entry, and
//! the round's size is never a value they contend on. The pot is a delta
//! for the same reason.
//!
//! Paying the pot out to the winner is a later leg this package does not
//! have. What it settles is who won, which is the part randomness
//! decides.

wit_bindgen::generate!({
    path: ["../../crates/sdk/wit/deps/kernel", "wit"],
    world: "test:guest/lottery",
    generate_all,
});

use hyperscale::kernel::env::randomness;
use hyperscale::kernel::events::emit;
use hyperscale::kernel::state::{
    delta_cell_add, range_read_count, range_read_entry, range_write_insert, write_cell_set,
};

/// The lottery's event table: the indexes a consumer resolves against
/// this package's metadata.
const ENTERED: u32 = 0;
const DRAWN: u32 = 1;

struct Lottery;

impl Guest for Lottery {
    fn enter(tickets: &RangeWrite, pot: &DeltaCell, order: Vec<u8>, who: Vec<u8>, amount: Vec<u8>) {
        // The ticket holds the entrant, because the order key is a hash
        // and a hash names no winner: the draw has to be able to say who
        // it picked, not merely which slot.
        range_write_insert(tickets, &order, &who);
        delta_cell_add(pot, &amount);
        emit(ENTERED, &who);
    }

    fn draw(outcome: &WriteCell, tickets: &RangeRead) {
        let draw = randomness();
        let mut settled = draw.clone();
        let entrants = range_read_count(tickets);
        if entrants > 0 {
            // The draw is 32 bytes and an index needs far fewer; the
            // modulo's bias is over the top 128 bits of a space the
            // entrant count never approaches.
            let seed = u128::from_le_bytes(draw[..16].try_into().unwrap());
            let winner = (seed % u128::from(entrants)) as u32;
            settled.extend_from_slice(&range_read_entry(tickets, winner));
        }
        // A round nobody entered still drew: the draw is recorded, no
        // winner follows it, and the pot stands for the next round.
        // Refusing here would let an empty round wedge the lottery.
        write_cell_set(outcome, &settled);
        emit(DRAWN, &settled);
    }
}

export!(Lottery);
