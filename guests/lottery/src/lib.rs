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
    struct Entered {
        who: Address,
    }

    /// What a draw declines with.
    #[error]
    enum Error {
        /// The page bought did not provably cover the round: the sweep
        /// came back full, so tickets past the cap may exist, and a
        /// winner drawn over a truncated round would disenfranchise
        /// them silently. Retry with a larger cap.
        RoundTruncated,
    }

    /// The round settled on a draw.
    #[event]
    struct Drawn(Outcome);

    /// A settled round: the draw, and the entrant it selected.
    ///
    /// A round nobody entered still drew, so the winner is optional and
    /// the draw is not.
    #[record]
    #[derive(Clone)]
    struct Outcome {
        draw: [u8; DRAW_BYTES],
        winner: Option<Address>,
    }

    /// The width the deterministic environment draws in.
    const DRAW_BYTES: usize = 32;

    #[state]
    struct Lottery {
        /// One entry per entrant, at the entrant's hashed order, so a
        /// second entry from one address lands on its own ticket.
        tickets: Unordered<Address>,
        /// The settled round.
        outcome: Cell<Option<Outcome>>,
    }

    impl Lottery {
        /// Take a ticket for `who`, staking `funds` into the pot.
        pub fn enter(&mut self, who: Address, funds: Bucket) {
            // The ticket holds the entrant, because the order key is a
            // hash and a hash names no winner: the draw has to be able to
            // say who it picked, not merely which slot.
            self.tickets.at(who).set(who);
            self.vault(funds.resource()).put(funds);
            Entered { who }.emit();
        }

        /// Settle the round on the transaction's own randomness, over
        /// every ticket the round holds.
        ///
        /// The caller buys the page and pays for it as the walk it
        /// declares; what no caller chooses is which tickets count. A
        /// sweep that returns fewer entries than its cap has exhausted
        /// the collection, so the winner is drawn over the whole round
        /// or the round declines — a page that comes back full proves
        /// nothing about what lies past it.
        pub fn draw(&mut self, cap: u64) -> Result<(), Error> {
            let draw = randomness();
            let window = self.tickets.sweep(0, cap);
            if u64::from(window.count()) == cap {
                return Err(Error::RoundTruncated);
            }
            // A round nobody entered still drew: the draw is recorded, no
            // winner follows it, and the pot stands for the next round.
            // Refusing here would let an empty round wedge the lottery.
            let winner = window.pick(&draw);
            // The width is the environment's, and the record states it:
            // a draw that is not thirty-two bytes is a defect in the
            // kernel rather than in this round.
            let settled = Outcome {
                draw: draw.try_into().expect("the draw is a thirty-two byte word"),
                winner,
            };
            self.outcome.set(Some(settled.clone()));
            Drawn(settled).emit();
            Ok(())
        }
    }
}
