//! A perpetual position: margin posted against a size, marked to an
//! oracle, and charged funding for as long as it is held.
//!
//! # What funding is, and why it is cumulative
//!
//! A perpetual has no expiry, so nothing drags its price back to the
//! thing it tracks except a payment between the two sides. When the
//! perpetual trades above the index, longs pay shorts; when it trades
//! below, shorts pay longs. The rate flips sign with the basis, and it
//! does so continually.
//!
//! Charging each position as the rate is posted would be work
//! proportional to how many positions exist, so the market carries one
//! cumulative number — quote per base, summed over every period — and a
//! position records where that number stood when it opened. What it owes
//! is its size times the distance the number has travelled since. That
//! distance is signed, because the number moves both ways.
//!
//! # The sign is held by hand
//!
//! `Fixed` is unsigned, so every signed quantity here is a magnitude and
//! a `bool` beside it, and every operation over one is a free function
//! below rather than an operator. `signed_add` is thirty lines that a
//! signed stored rate would make disappear.
//!
//! It is written this way deliberately. The question of whether the
//! vocabulary should carry a signed rate is answered by writing the
//! contract that wants one and reading what it cost, not by assuming.
//!
//! # What this deliberately is not
//!
//! One position and no counterparty: there is no matching engine, no
//! insurance fund and no auto-deleveraging. The vault is the other side
//! of every trade, which is a market maker's book rather than an
//! exchange's — and it is enough to make the arithmetic real, which is
//! what this is for.

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
        /// One where the position this market holds is long.
        ///
        /// Creation-fixed rather than stated per call, because a boolean
        /// is not a kind a manifest binds — the only one that crosses
        /// into a guest is a clause's own verdict. And an integer rather
        /// than a boolean even here, because a configured `bool` reaches
        /// the *declaration* and never the body: what a slot may hold and
        /// what a body may read are not the same set.
        ///
        /// A side chosen at creation is a market that is one side of the
        /// trade, which is what a single-position market is anyway.
        long: u64,
    }

    /// What an entry point declines with.
    #[error]
    enum Error {
        /// No mark has been posted, so nothing can be valued.
        MarkUnset,
        /// A position is already open, and this market holds one.
        AlreadyOpen,
        /// No position is open.
        NotOpen,
        /// The margin posted does not cover the maintenance requirement.
        BelowMaintenance,
        /// The position still covers its requirement.
        StillCovered,
    }

    #[state]
    struct Perp {
        /// What one base unit is worth, as the oracle last said.
        mark: Cell<Fixed<Quote, Base>>,
        /// Cumulative funding per base since the market opened, as a
        /// magnitude.
        funding: Cell<Fixed<Quote, Base>>,
        /// Whether that cumulative figure is negative: one for yes.
        ///
        /// An integer because a sign has nowhere better to go. A stored
        /// rate cannot carry one, and `bool` is not a kind a cell holds,
        /// so the flag is a number whose two meaningful values are a
        /// convention this guest keeps with itself.
        funding_negative: Cell<u64>,
        /// The open position's size, in base.
        size: Cell<Quantity>,
        /// What it posted as margin.
        ///
        /// Recorded rather than read off the vault, because the vault is
        /// also the market's own book — it is the other side of the
        /// trade and holds what it needs to pay a winner with.
        margin: Cell<Quantity>,
        /// The mark it opened at.
        entry: Cell<Fixed<Quote, Base>>,
        /// Where cumulative funding stood when it opened, and its sign.
        entry_funding: Cell<Fixed<Quote, Base>>,
        entry_funding_negative: Cell<u64>,
    }

    impl Perp {
        /// Post what one base unit is worth.
        #[requires(oracle)]
        pub fn post_mark(&mut self, mark: Fixed<Quote, Base>) {
            self.mark.set(mark);
        }

        /// Add one period's funding, with longs paying it.
        ///
        /// Two methods rather than one taking a direction, because the
        /// direction is a boolean and a boolean is not a kind a manifest
        /// binds. The rate cannot carry the sign either, so the sign is
        /// in the name.
        #[requires(oracle)]
        pub fn charge_longs(&mut self, rate: Fixed<Quote, Base>) {
            let (carried, negative) = signed_add(
                self.funding.get(),
                is_set(self.funding_negative.get()),
                rate,
                false,
            );
            self.funding.set(carried);
            self.funding_negative.set(flag(negative));
        }

        /// Add one period's funding, with shorts paying it.
        #[requires(oracle)]
        pub fn credit_longs(&mut self, rate: Fixed<Quote, Base>) {
            let (carried, negative) = signed_add(
                self.funding.get(),
                is_set(self.funding_negative.get()),
                rate,
                true,
            );
            self.funding.set(carried);
            self.funding_negative.set(flag(negative));
        }

        /// Open a position of `size`, posting `funds` as margin.
        pub fn open(&mut self, funds: Bucket, size: Quantity) -> Result<(), Error> {
            let collateral = self.config().collateral;
            let maintenance = self.config().maintenance_margin;
            let mut vault = self.vault(collateral);
            let posted = funds.quantity();
            vault.put(funds);

            if !self.size.get().is_zero() {
                return Err(Error::AlreadyOpen);
            }
            let mark = self.mark.get();
            if mark.is_zero() {
                return Err(Error::MarkUnset);
            }

            // A position opens covered or it does not open: the margin
            // has to clear the same bar it will later be liquidated
            // against.
            let notional = size.convert(mark.rate(), Rounding::Up);
            if posted < notional.scale(maintenance.ratio(), Rounding::Up) {
                return Err(Error::BelowMaintenance);
            }

            self.size.set(size);
            self.margin.set(posted);
            self.entry.set(mark);
            self.entry_funding.set(self.funding.get());
            self.entry_funding_negative.set(self.funding_negative.get());
            Ok(())
        }

        /// Close the position and take what it is worth.
        pub fn close(&mut self) -> Result<Bucket, Error> {
            let collateral = self.config().collateral;
            let mut vault = self.vault(collateral);
            let held = vault.balance();
            let posted = self.margin.get();

            let size = self.size.get();
            if size.is_zero() {
                return Err(Error::NotOpen);
            }
            let mark = self.mark.get();
            let long = is_set(self.config().long);

            // The profit and the loss, as two unsigned branches rather
            // than one signed difference: a long gains what the mark rose
            // and loses what it fell, and a short is the same sentence
            // the other way round.
            let now = size.convert(mark.rate(), Rounding::Down);
            let then = size.convert(self.entry.get().rate(), Rounding::Down);
            let (profit, loss) = if long {
                (now.saturating_sub(then), then.saturating_sub(now))
            } else {
                (then.saturating_sub(now), now.saturating_sub(then))
            };

            // What funding has done since the position opened: the
            // distance the cumulative figure travelled, which is a signed
            // subtraction spelled as an addition of a flipped sign.
            let (drift, drift_negative) = signed_add(
                self.funding.get(),
                is_set(self.funding_negative.get()),
                self.entry_funding.get(),
                !is_set(self.entry_funding_negative.get()),
            );
            let moved = size.convert(drift.rate(), Rounding::Up);
            // A long pays when the figure rose and is paid when it
            // fell; a short is the same sentence reversed.
            let pays = if drift_negative { !long } else { long };
            let (paid, received) = if pays {
                (moved, Quantity::ZERO)
            } else {
                (Quantity::ZERO, moved)
            };

            // Floored at nothing: a position that owes more than it
            // posted is bad debt this market absorbs, which is what
            // having no insurance fund means.
            let equity = (posted + profit + received).saturating_sub(loss + paid);

            self.size.set(Quantity::ZERO);
            self.margin.set(Quantity::ZERO);
            // Bounded by what the vault holds: this market is the other
            // side of the trade and cannot pay out more than it has.
            Ok(vault.take(equity.min(held)))
        }

        /// Seize a position that no longer covers its requirement.
        pub fn liquidate(&mut self) -> Result<Bucket, Error> {
            let collateral = self.config().collateral;
            let maintenance = self.config().maintenance_margin;
            let bonus = self.config().liquidation_bonus;
            let mut vault = self.vault(collateral);
            let held = vault.balance();
            let posted = self.margin.get();

            let size = self.size.get();
            if size.is_zero() {
                return Err(Error::NotOpen);
            }
            let mark = self.mark.get();
            let long = is_set(self.config().long);

            // The profit and the loss, as two unsigned branches rather
            // than one signed difference: a long gains what the mark rose
            // and loses what it fell, and a short is the same sentence
            // the other way round.
            let now = size.convert(mark.rate(), Rounding::Down);
            let then = size.convert(self.entry.get().rate(), Rounding::Down);
            let (profit, loss) = if long {
                (now.saturating_sub(then), then.saturating_sub(now))
            } else {
                (then.saturating_sub(now), now.saturating_sub(then))
            };

            // What funding has done since the position opened: the
            // distance the cumulative figure travelled, which is a signed
            // subtraction spelled as an addition of a flipped sign.
            let (drift, drift_negative) = signed_add(
                self.funding.get(),
                is_set(self.funding_negative.get()),
                self.entry_funding.get(),
                !is_set(self.entry_funding_negative.get()),
            );
            let moved = size.convert(drift.rate(), Rounding::Up);
            // A long pays when the figure rose and is paid when it
            // fell; a short is the same sentence reversed.
            let pays = if drift_negative { !long } else { long };
            let (paid, received) = if pays {
                (moved, Quantity::ZERO)
            } else {
                (Quantity::ZERO, moved)
            };

            // Floored at nothing: a position that owes more than it
            // posted is bad debt this market absorbs, which is what
            // having no insurance fund means.
            let equity = (posted + profit + received).saturating_sub(loss + paid);

            let notional = size.convert(mark.rate(), Rounding::Down);
            if equity >= notional.scale(maintenance.ratio(), Rounding::Down) {
                return Err(Error::StillCovered);
            }

            self.size.set(Quantity::ZERO);
            self.margin.set(Quantity::ZERO);
            // The liquidator's cut, and what stays with the market: a
            // division of what was seized rather than two numbers that
            // have to agree.
            let (cut, _kept) = equity.min(held).divide(bonus.ratio());
            Ok(vault.take(cut))
        }
    }

    /// Whether a stored two-valued fact is set.
    ///
    /// Signs and sides both come through here, because neither has a
    /// type of its own in a cell.
    fn is_set(flag: u64) -> bool {
        flag == 1
    }

    /// The integer a two-valued fact is stored as.
    fn flag(set: bool) -> u64 {
        u64::from(set)
    }

    /// A signed sum of two magnitudes, normalized so zero is never
    /// negative.
    ///
    /// Every line of this is what a signed stored rate would carry
    /// itself. It is here because the vocabulary has no such type, and
    /// it is written out rather than hidden so that the cost of not
    /// having one is visible.
    fn signed_add(
        magnitude: Fixed<Quote, Base>,
        negative: bool,
        delta: Fixed<Quote, Base>,
        delta_negative: bool,
    ) -> (Fixed<Quote, Base>, bool) {
        if negative == delta_negative {
            let sum = magnitude + delta;
            return (sum, negative && !sum.is_zero());
        }
        if magnitude >= delta {
            let rest = magnitude - delta;
            return (rest, negative && !rest.is_zero());
        }
        let rest = delta - magnitude;
        (rest, delta_negative && !rest.is_zero())
    }
}
