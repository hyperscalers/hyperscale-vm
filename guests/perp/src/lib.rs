//! A perpetual position: margin posted against a size, marked to an
//! oracle, and charged funding for as long as it is held.
//!
//! # What funding is, and why it is two counters
//!
//! A perpetual has no expiry, so nothing drags its price back to the
//! thing it tracks except a payment between the two sides. When the
//! perpetual trades above the index, longs pay shorts; when it trades
//! below, shorts pay longs. The payment flips direction with the basis,
//! and it does so continually.
//!
//! Charging each position as the rate is posted would be work
//! proportional to how many positions exist, so the market carries the
//! figure forward and a position records where it stood when the position
//! opened. What it owes is its size times the distance travelled since.
//!
//! That distance is signed, and the market holds it as **two monotone
//! counters** rather than as one signed figure: everything charged to
//! longs, and everything credited to them. Each is only ever added to, so
//! a position's share of either is a counter less a snapshot of itself —
//! total by construction, with no underflow to guard.
//!
//! The reason is rounding, not storage. What a position pays should round
//! up and what it receives should round down, both in the market's
//! favour. A single netted figure cannot say that: by the time the two
//! directions are one number they are indistinguishable, and the one
//! conversion left has to guess. Two counters keep them apart all the way
//! to the two conversions that need them apart.
//!
//! A *signed* rate is the right shape for a value somebody **sets** — see
//! `guests/peg`, where an oracle posts one. It is the wrong shape for one
//! that accumulates.
//!
//! # What this deliberately is not
//!
//! One position and no counterparty: there is no matching engine, no
//! insurance fund and no auto-deleveraging. The vault is the other side
//! of every trade, which is a market maker's book rather than an
//! exchange's — and it is enough to make the arithmetic real, which is
//! what this is for.
//!
//! Nothing comes back to the trader on a liquidation. What the keeper
//! does not take stays with the market, because there is no insurance
//! fund for it to reach and no second side to owe it. A real venue
//! returns the residual, and a reader should not take this one for a
//! model of how.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod perp {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Fixed, Quantity, Rounding, UnitFixed};
    use hyperscale_vm_sdk::{Address, ResourceAddr};

    /// What the perpetual tracks.
    pub struct Base;
    /// What it is priced and settled in.
    pub struct Quote;

    /// The market's creation-fixed terms.
    #[config]
    struct Terms {
        /// What margin is posted in, and what a position settles in.
        collateral: ResourceAddr,
        /// Who may post a mark and a funding rate.
        oracle: Address,
        /// The share of notional a position must keep as equity.
        maintenance_margin: UnitFixed,
        /// What a liquidator takes of what it seizes.
        liquidation_bonus: UnitFixed,
        /// Whether the position this market holds is long.
        ///
        /// Creation-fixed rather than stated per call: a side chosen at
        /// creation is a market that is one side of the trade, which is
        /// what a single-position market is anyway.
        long: bool,
    }

    /// What an entry point declines with.
    #[error]
    enum Error {
        /// No mark has been posted, so nothing can be valued.
        MarkUnset,
        /// A position of no size, which is not a position.
        EmptyPosition,
        /// The margin posted does not cover the maintenance requirement.
        BelowMaintenance,
        /// The position still covers its requirement.
        StillCovered,
    }

    /// What one open position is.
    ///
    /// One record rather than a leaf per field, so that "is a position
    /// open" is the leaf's presence rather than a magnitude a body reads.
    /// A size of zero used to answer that question, which made a position
    /// of no size indistinguishable from no position — and the margin
    /// posted beside it unreachable.
    #[record]
    struct Position {
        /// Its size, in base.
        size: Quantity,
        /// What it posted as margin.
        ///
        /// Recorded rather than read off the vault, because the vault is
        /// also the market's own book — it is the other side of the
        /// trade and holds what it needs to pay a winner with.
        margin: Quantity,
        /// The mark it opened at.
        entry: Fixed<Quote, Base>,
        /// Where the charged counter stood when it opened.
        entry_charged: Fixed<Quote, Base>,
        /// And the credited one.
        entry_credited: Fixed<Quote, Base>,
    }

    #[state]
    struct Perp {
        /// What one base unit is worth, as the oracle last said.
        mark: Cell<Fixed<Quote, Base>>,
        /// Everything charged to longs since the market opened.
        funding_charged: Cell<Fixed<Quote, Base>>,
        /// Everything credited to them.
        funding_credited: Cell<Fixed<Quote, Base>>,
        /// The open position, where there is one.
        position: Cell<Option<Position>>,
    }

    impl Perp {
        /// Post what one base unit is worth.
        #[requires(config.oracle)]
        pub fn post_mark(&mut self, mark: Fixed<Quote, Base>) {
            self.mark.set(mark);
        }

        /// Add one period's funding, with longs paying it.
        ///
        /// Two methods rather than one taking a direction, and now for a
        /// reason rather than for want of one: they write two different
        /// counters, which is what keeps the two directions roundable
        /// apart.
        #[requires(config.oracle)]
        pub fn charge_longs(&mut self, rate: Fixed<Quote, Base>) {
            self.funding_charged.set(self.funding_charged.get() + rate);
        }

        /// Add one period's funding, with shorts paying it.
        #[requires(config.oracle)]
        pub fn credit_longs(&mut self, rate: Fixed<Quote, Base>) {
            self.funding_credited
                .set(self.funding_credited.get() + rate);
        }

        /// Open a position of `size`, posting `funds` as margin.
        ///
        /// A market already holding one refuses at admission rather than
        /// here: the record's leaf must be absent for this to run, which
        /// is a fact the declaration states and no body has to check.
        pub fn open(&mut self, funds: Bucket, size: Quantity) -> Result<(), Error> {
            let terms = self.config();
            let posted = funds.quantity();
            let mark = self.mark.get();

            if size.is_zero() {
                return Err(Error::EmptyPosition);
            }
            if mark.is_zero() {
                return Err(Error::MarkUnset);
            }
            // A position opens covered or it does not open: the margin
            // has to clear the same bar it will later be liquidated
            // against.
            let notional = size.convert(mark.rate(), Rounding::Up);
            if posted < notional.scale(terms.maintenance_margin.ratio(), Rounding::Up) {
                return Err(Error::BelowMaintenance);
            }

            let entry_charged = self.funding_charged.get();
            let entry_credited = self.funding_credited.get();
            self.vault(terms.collateral).put(funds);
            self.position.create(Position {
                size,
                margin: posted,
                entry: mark,
                entry_charged,
                entry_credited,
            });
            Ok(())
        }

        /// Close the position and take what it is worth.
        pub fn close(&mut self) -> Bucket {
            let terms = self.config();
            let mut vault = self.vault(terms.collateral);
            let held = vault.balance();
            let position = self.position.existing();

            let worth = equity(
                &position,
                self.mark.get(),
                self.funding_charged.get(),
                self.funding_credited.get(),
                terms.long,
            );

            self.position.retire();
            // Bounded by what the vault holds: this market is the other
            // side of the trade and cannot pay out more than it has.
            vault.take(worth.min(held))
        }

        /// Seize a position that no longer covers its requirement.
        pub fn liquidate(&mut self) -> Result<Bucket, Error> {
            let terms = self.config();
            let mut vault = self.vault(terms.collateral);
            let held = vault.balance();
            let position = self.position.existing();

            let mark = self.mark.get();
            let worth = equity(
                &position,
                mark,
                self.funding_charged.get(),
                self.funding_credited.get(),
                terms.long,
            );
            let notional = position.size.convert(mark.rate(), Rounding::Down);
            if worth >= notional.scale(terms.maintenance_margin.ratio(), Rounding::Down) {
                return Err(Error::StillCovered);
            }

            self.position.retire();
            // The liquidator's cut, and what stays with the market: a
            // division of what was seized rather than two numbers that
            // have to agree.
            let (cut, _kept) = worth.min(held).divide(terms.liquidation_bonus.ratio());
            Ok(vault.take(cut))
        }
    }

    /// What a position is worth right now, floored at nothing.
    ///
    /// A free function over values already read, which is how the two
    /// bodies that settle a position share one calculation: a method
    /// cannot call another method of its own component, because each
    /// declares only its own accesses, and lifting the reads to
    /// parameters is what that refusal points at.
    ///
    /// Floored because a position that owes more than it posted is bad
    /// debt this market absorbs, which is what having no insurance fund
    /// means.
    fn equity(
        position: &Position,
        mark: Fixed<Quote, Base>,
        charged: Fixed<Quote, Base>,
        credited: Fixed<Quote, Base>,
        long: bool,
    ) -> Quantity {
        // The profit and the loss, as two unsigned branches rather than
        // one signed difference: a long gains what the mark rose and
        // loses what it fell, and a short is the same sentence the other
        // way round.
        let now = position.size.convert(mark.rate(), Rounding::Down);
        let then = position.size.convert(position.entry.rate(), Rounding::Down);
        let (profit, loss) = if long {
            (now.saturating_sub(then), then.saturating_sub(now))
        } else {
            (then.saturating_sub(now), now.saturating_sub(then))
        };

        // What each counter did while the position was open. Both are a
        // counter less a snapshot of itself, so neither runs below zero.
        let longs_paid = charged - position.entry_charged;
        let longs_took = credited - position.entry_credited;
        let (owed, due) = if long {
            (longs_paid, longs_took)
        } else {
            (longs_took, longs_paid)
        };
        // Up on what the position pays and down on what it is paid,
        // which favours the market at both ends — and is the whole reason
        // the two directions are kept apart this far.
        let paid = position.size.convert(owed.rate(), Rounding::Up);
        let received = position.size.convert(due.rate(), Rounding::Down);

        (position.margin + profit + received).saturating_sub(loss + paid)
    }
}
