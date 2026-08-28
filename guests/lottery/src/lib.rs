//! The lottery: entries into a pot, and a winner nobody could have
//! arranged.
//!
//! A round runs in two legs. `close` seals the draw that will settle it;
//! `settle` opens the seal once the protocol has rolled the seed it
//! commits to, and picks the winner over every ticket the round holds.
//! A third, `reopen`, is the way back from a round nobody settled while
//! its seed was still kept — the tickets stay and only the draw is taken
//! again, and the kernel refuses it over a seal that can still open.
//!
//! The two legs are the whole point. A draw a transaction carries is a
//! draw the proposer of the block committing that transaction knows
//! before it decides what the block contains — so a winner picked from
//! one is a winner somebody could have arranged. A sealed draw is a
//! function of committed state and of a seed rolled after the sealing
//! commits, so retrying settles the same way, abandoning an attempt
//! gains nothing, and there is no attempt anyone can grind.
//!
//! Entry closes when the round does, and that is not tidiness: a seed is
//! public once rolled, and so is the word derived from it, so anyone can
//! compute a settled round's winning position before settling it. An
//! entrant admitted after the seal could buy the ticket that sits there.
//! The seal's absence is what `enter` declares against — a fresh read,
//! so two people entering at once still commute and only the close
//! orders against them.
//!
//! The result cell records the draw beside the winner. A lottery that
//! publishes only its winner asks to be trusted about how it got one —
//! publishing the draw lets a reader check it against the seed the round
//! committed to, and lets two shards settling one transaction be
//! compared against each other.
//!
//! Entrants are the tickets collection rather than a list in a cell, so
//! two people entering at once commute: each writes its own entry, and
//! the round's size is never a value they contend on. The pot is a delta
//! for the same reason.
//!
//! Paying the pot out to the winner is a later leg this package does not
//! have. What it settles is who won, which is the part the draw decides.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod lottery {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{
        Bucket, Cell, Drawn, Keyed, OrderKey, Seal, Unordered, Vault, Word,
    };

    /// Somebody took a ticket.
    #[event]
    struct Entered {
        who: Address,
    }

    /// The round closed on a seal.
    #[event]
    struct Closed;

    /// What a settlement declines with.
    #[error]
    enum Error {
        /// The page bought did not cover the round: tickets past the
        /// cap exist, and a winner drawn over a truncated round would
        /// disenfranchise them silently. Retry with a larger cap.
        RoundTruncated,
        /// The seed this round's seal commits to is not rolled yet.
        /// Nothing is wrong; settle again later.
        NotYetDrawn,
        /// The seal will never open. Nobody settled the round inside the
        /// window its seed is kept in, so the round has to be reopened —
        /// onto a seal whose seed nobody has seen.
        SealLapsed,
        /// The round's seal can still open, so there is nothing to
        /// reopen: settle it.
        RoundStandsOpen,
    }

    /// The round settled on a draw.
    #[event]
    struct Settled(Outcome);

    /// A settled round: the draw, and the entrant it selected.
    ///
    /// A round nobody entered still drew, so the winner is optional and
    /// the draw is not.
    #[record]
    struct Outcome {
        draw: Word,
        winner: Option<Address>,
    }

    #[state]
    struct Lottery {
        /// The pot: one vault per resource entries arrived in.
        pot: Keyed<Vault>,
        /// One entry per entrant, at the entrant's hashed order, so a
        /// second entry from one address lands on its own ticket.
        tickets: Unordered<Address>,
        /// The draw this round will settle on, once it is closed.
        round: Cell<Option<Seal>>,
        /// The settled round.
        outcome: Cell<Option<Outcome>>,
    }

    impl Lottery {
        /// Take a ticket for `who`, staking `funds` into the pot.
        pub fn enter(&mut self, who: Address, funds: Bucket) {
            // Only while the round is open, and read rather than held:
            // what stops a late entrant is the seal being there, and
            // holding it would make every entry wait on every other.
            self.round.vacant();
            // The ticket holds the entrant, because the order key is a
            // hash and a hash names no winner: the draw has to be able to
            // say who it picked, not merely which slot.
            self.tickets.at(who).set(who);
            self.pot.at(funds.resource()).put(funds);
            Entered { who }.emit();
        }

        /// Close the round on a seal, ending entry.
        ///
        /// Public, and there is nothing an operator would be trusted
        /// with: the seal takes no argument at all — the kernel stamps
        /// the epoch — so whoever closes the round chooses when it
        /// closes and not what it draws.
        pub fn close(&mut self) {
            self.round.seal();
            Closed.emit();
        }

        /// Take a second seal, where the round's own will never open.
        ///
        /// The way back from [`Error::SealLapsed`], and the reason a
        /// lapse is worth telling apart from a round that is merely
        /// early. The tickets stay: what lapsed is the draw that would
        /// have decided the round, not the round.
        ///
        /// Nothing here judges whether the seal may be replaced — the
        /// kernel refuses a reseal over one that can still open, so a
        /// caller waiting for a word they liked better cannot get one.
        /// The branch below is what turns that refusal into an error a
        /// caller can read.
        pub fn reopen(&mut self) -> Result<(), Error> {
            // A settled round is over, and resealing one would leave a
            // seal nothing will ever open again.
            self.outcome.vacant();
            // Early or matured, a seal that can still answer is a round
            // to settle rather than one to take again.
            let Drawn::Expired = self.round.open() else {
                return Err(Error::RoundStandsOpen);
            };
            self.round.reseal();
            Closed.emit();
            Ok(())
        }

        /// Settle the round over every ticket it holds.
        ///
        /// The caller buys the page and pays for it as the walk it
        /// declares; what no caller chooses is which tickets count. The
        /// kernel answers whether the page covered the round, so the
        /// winner is drawn over the whole round or the round declines —
        /// and a page exactly the round's size still settles.
        ///
        /// A round settles once. The outcome is written where nothing
        /// was, so a second settlement is infeasible against a round
        /// that already has one, refused where the declaration is judged
        /// rather than by anything here.
        pub fn settle(&mut self, cap: u64) -> Result<(), Error> {
            let draw = match self.round.open() {
                Drawn::Pending => return Err(Error::NotYetDrawn),
                Drawn::Expired => return Err(Error::SealLapsed),
                Drawn::Ready(draw) => draw,
            };
            let window = self.tickets.sweep(OrderKey::at(0, 0), cap);
            if !window.covered() {
                return Err(Error::RoundTruncated);
            }
            // A round nobody entered still drew: the draw is recorded and
            // no winner follows it. Refusing here would leave a round
            // that nobody can settle and nobody can abandon.
            let settled = Outcome {
                draw: draw.word(),
                winner: window.pick(draw),
            };
            self.outcome.create(settled.clone());
            Settled(settled).emit();
            Ok(())
        }
    }
}
