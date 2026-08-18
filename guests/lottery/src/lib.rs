//! The lottery: entries into a pot, and a winner chosen by the
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
//! have. What it settles is who won, which is the part randomness decides.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod lottery {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Cell, Unordered, randomness};

    /// Somebody took a ticket.
    #[event]
    struct Entered;

    /// The round settled on a draw.
    #[event]
    struct Drawn;

    #[state]
    struct Lottery {
        /// One entry per entrant, at the entrant's hashed order, so a
        /// second entry from one address lands on its own ticket.
        tickets: Unordered<Vec<u8>>,
        /// The settled round: the draw, and the entrant it selected.
        outcome: Cell<Vec<u8>>,
    }

    impl Lottery {
        /// Take a ticket for `who`, staking `funds` into the pot.
        pub fn enter(&mut self, who: Address, funds: Bucket) {
            // The ticket holds the entrant, because the order key is a
            // hash and a hash names no winner: the draw has to be able to
            // say who it picked, not merely which slot.
            self.tickets.at(who).set(who.to_bytes().to_vec());
            self.vault(funds.resource()).put(funds);
            Entered::emit(&who.to_bytes());
        }

        /// Settle the round on the transaction's own randomness.
        pub fn draw(&mut self) {
            let draw = randomness();
            let mut settled = draw.clone();
            let tickets = self.tickets.sweep(0, 64);
            let entrants = tickets.count();
            if entrants > 0 {
                // The draw is 32 bytes and an index needs far fewer; the
                // modulo's bias is over the top 128 bits of a space the
                // entrant count never approaches.
                let seed = u128::from_le_bytes(draw[..16].try_into().unwrap());
                // The remainder is below the entrant count, which is a
                // `u32` to begin with.
                #[allow(clippy::cast_possible_truncation)]
                let winner = (seed % u128::from(entrants)) as u32;
                settled.extend_from_slice(&tickets.entry(winner));
            }
            // A round nobody entered still drew: the draw is recorded, no
            // winner follows it, and the pot stands for the next round.
            // Refusing here would let an empty round wedge the lottery.
            self.outcome.set(settled.clone());
            Drawn::emit(&settled);
        }
    }
}
