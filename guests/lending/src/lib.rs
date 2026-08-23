//! A collateralized borrowing position: collateral in one resource, debt
//! in another, and a judgment between them that has to cross a numeraire.
//!
//! # Why the index is a stored rate
//!
//! What a position owes grows with time, and writing that growth into
//! every position on every block is work proportional to how many
//! positions exist. So the position stores *shares* of the debt and the
//! contract stores one rate — debt subunits per share — that carries
//! forward on its own. A position's debt is its shares valued at the
//! index, computed when someone asks.
//!
//! The index is the one number here that outlives a transaction, which is
//! what makes it a `Fixed` rather than a fraction: it is added to and
//! multiplied across a great many transactions, and a representation that
//! re-rounds on every one of them would drift away from what anybody
//! could recompute.
//!
//! # Why accrual is its own method
//!
//! `borrow`, `repay` and `liquidate` all refuse an index that has not
//! been carried to the period they were handed. They could each carry it
//! themselves, and then the same four lines would be written four times
//! and a body would declare a write it usually does not need.
//!
//! Instead a manifest composes `accrue` with whatever it meant to do,
//! which is what a manifest is for. The staleness becomes a refusal an
//! author can read rather than a silent read of an old number.
//!
//! # What this deliberately is not
//!
//! One position, not a pool: there is no lender side, no supply
//! redemption and no reserve factor. The debt vault is funded from
//! outside. What is here is the arithmetic a lending market is wrong
//! about when it is wrong — the index, the cross-resource comparison,
//! and the threshold — and none of that needs a second side to be real.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod lending {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Fixed, Quantity, Rounding, UnitFixed, Wide};
    use hyperscale_vm_sdk::{Address, ResourceAddr};

    /// What a position posts. A dimension, not a value.
    struct Collateral;
    /// What it owes.
    struct Debt;
    /// A share of the debt, which is what the position actually holds.
    struct Share;
    /// The unit both sides are compared in.
    struct Numeraire;

    /// The market's creation-fixed terms.
    #[config]
    struct Terms {
        /// What a position posts.
        collateral: ResourceAddr,
        /// What it borrows.
        debt: ResourceAddr,
        /// Who may post a price. A price anyone could post is a
        /// liquidation anyone could manufacture.
        oracle: Address,
        /// The most of a position's collateral value it may owe when it
        /// borrows.
        ltv: UnitFixed,
        /// The ratio of debt to collateral above which anyone may
        /// liquidate. Above `ltv`, so a position does not open already
        /// liquidatable.
        liquidation_threshold: UnitFixed,
        /// What the debt is multiplied by each period, at the stored
        /// rate's own scale. One means a market that charges nothing.
        growth_per_period: u128,
    }

    /// What an entry point declines with.
    #[error]
    enum Error {
        /// No price has been posted, so nothing can be judged.
        PriceUnset,
        /// The index has not been carried to this period. Compose the
        /// call with `accrue`.
        IndexStale,
        /// The position would owe more than its collateral allows.
        OverLtv,
        /// The position still covers its debt, so nothing may be seized.
        StillCovered,
        /// The position owes nothing.
        NothingOwed,
    }

    #[state]
    struct Lending {
        /// Debt subunits per share: what turns what a position holds
        /// into what it owes.
        index: Cell<Fixed<Debt, Share>>,
        /// What one collateral subunit is worth in the numeraire.
        collateral_price: Cell<Fixed<Numeraire, Collateral>>,
        /// What one debt subunit is worth in the numeraire.
        debt_price: Cell<Fixed<Numeraire, Debt>>,
        /// What this position owes, in shares.
        shares: Cell<Quantity>,
        /// The period the index has been carried to.
        accrued_at: Cell<u64>,
    }

    impl Lending {
        /// Post what the two sides are worth.
        ///
        /// Both at once, because a judgment reads both and a market that
        /// could update one alone would have a window where the pair
        /// disagrees about when it was priced.
        #[requires(oracle)]
        pub fn post_price(&mut self, collateral: u128, debt: u128) {
            self.collateral_price
                .set(Fixed::from_scaled(Wide::from_u128(collateral)));
            self.debt_price
                .set(Fixed::from_scaled(Wide::from_u128(debt)));
        }

        /// Carry the debt index forward to `now`.
        ///
        /// Compounding is one exponentiation rather than a loop: the
        /// growth over a span is the per-period growth raised to it, and
        /// squaring gets there in a bounded number of multiplications
        /// however long the span.
        pub fn accrue(&mut self, now: u64) {
            let last = self.accrued_at.get();
            let periods = u32::try_from(now.saturating_sub(last)).unwrap_or(u32::MAX);
            let growth =
                Fixed::<(), ()>::from_scaled(Wide::from_u128(self.config().growth_per_period))
                    .pow_int(periods, Rounding::Down);

            // The composition happens on the exact fractions and
            // quantizes once, which is the only lossy step. Down, so the
            // market never charges a subunit it cannot derive.
            let carried = started(self.index.get())
                .rate()
                .ratio()
                .compose(growth.rate().ratio());
            self.index.set(carried.quantize_as(Rounding::Down));
            self.accrued_at.set(now);
        }

        /// Post collateral against the position, and answer with what
        /// the position now holds.
        ///
        /// The read is what makes this site exclusive rather than
        /// commutative, and that is load-bearing rather than incidental.
        /// A body that only credited would declare a delta — a blind
        /// increment, which is the cheaper and more parallel thing — and
        /// a delta is not observable until it settles. So a manifest that
        /// deposited and then drew in the same transaction would price
        /// the draw against the collateral that was there *before* the
        /// deposit, and be refused for a position it had just funded.
        ///
        /// Answering with the new total is what makes the read mean
        /// something to a caller as well as to the mode.
        pub fn deposit(&mut self, funds: Bucket) -> Quantity {
            let mut posted = self.vault(self.config().collateral);
            let held = posted.balance() + funds.quantity();
            posted.put(funds);
            held
        }

        /// Draw debt against the collateral posted.
        ///
        /// Up wherever the number decides what the position owes, and
        /// down wherever it decides what the position is worth: a
        /// rounding that flatters the borrower is one the market pays
        /// for.
        pub fn draw(&mut self, want: Quantity, now: u64) -> Result<Bucket, Error> {
            // The terms are read out rather than held, because the record
            // borrows the component and the body writes to it.
            let collateral_resource = self.config().collateral;
            let debt_resource = self.config().debt;
            let ltv = self.config().ltv;
            if self.accrued_at.get() != now {
                return Err(Error::IndexStale);
            }
            let collateral_price = self.collateral_price.get();
            let debt_price = self.debt_price.get();
            if collateral_price.is_zero() || debt_price.is_zero() {
                return Err(Error::PriceUnset);
            }

            let index = started(self.index.get());
            // What the drawn debt is worth in shares, taken the other way
            // round on the exact fraction rather than by inverting a
            // quantized rate and multiplying back.
            let Ok(per_debt) = index.recip_rate() else {
                return Err(Error::NothingOwed);
            };
            let drawn = want.convert(per_debt, Rounding::Up);
            let owed = (self.shares.get() + drawn).convert(index.rate(), Rounding::Up);

            let posted = self.vault(collateral_resource).balance();
            let backing = posted.convert(collateral_price.rate(), Rounding::Down);
            let exposure = owed.convert(debt_price.rate(), Rounding::Up);
            if exposure > backing.scale(ltv.ratio(), Rounding::Down) {
                return Err(Error::OverLtv);
            }

            self.shares.set(self.shares.get() + drawn);
            Ok(self.vault(debt_resource).take(want))
        }

        /// Hand debt back and retire the shares it stood for.
        pub fn repay(&mut self, funds: Bucket, now: u64) -> Result<(), Error> {
            let mut owed_vault = self.vault(self.config().debt);
            let paid = funds.quantity();
            // The payment lands before the judgment, because a body
            // leaves by no path holding value.
            owed_vault.put(funds);
            if self.accrued_at.get() != now {
                return Err(Error::IndexStale);
            }

            let index = started(self.index.get());
            let Ok(per_debt) = index.recip_rate() else {
                return Err(Error::NothingOwed);
            };
            // Down on retirement, so a payment never retires more debt
            // than it covers.
            let retired = paid.convert(per_debt, Rounding::Down);
            self.shares.set(self.shares.get().saturating_sub(retired));
            Ok(())
        }

        /// Seize the collateral of a position that no longer covers what
        /// it owes.
        ///
        /// The judgment is a comparison of two fractions rather than of
        /// two amounts: what a position owes over what it posted is a
        /// fraction, and the threshold is one too, so neither side has to
        /// be materialized as a quantity and rounded on the way there.
        ///
        /// Debt over collateral rather than the other way round, because
        /// the bounded type a threshold is written in runs to one — and
        /// a market is in trouble when this number rises, which is the
        /// direction that fits inside it.
        pub fn liquidate(&mut self, now: u64) -> Result<Bucket, Error> {
            let collateral_resource = self.config().collateral;
            let threshold = self.config().liquidation_threshold;
            if self.accrued_at.get() != now {
                return Err(Error::IndexStale);
            }
            let collateral_price = self.collateral_price.get();
            let debt_price = self.debt_price.get();
            if collateral_price.is_zero() || debt_price.is_zero() {
                return Err(Error::PriceUnset);
            }

            let index = started(self.index.get());
            let owed = self.shares.get().convert(index.rate(), Rounding::Up);
            if owed.is_zero() {
                return Err(Error::NothingOwed);
            }

            let mut posted = self.vault(collateral_resource);
            let backing = posted
                .balance()
                .convert(collateral_price.rate(), Rounding::Down);
            let exposure = owed.convert(debt_price.rate(), Rounding::Up);
            let Ok(utilisation) = exposure.ratio_to(backing) else {
                return Err(Error::NothingOwed);
            };
            if utilisation.cmp_with(threshold.ratio()).is_le() {
                return Err(Error::StillCovered);
            }

            self.shares.set(Quantity::ZERO);
            let seized = posted.balance();
            Ok(posted.take(seized))
        }

        /// The index as a plain number, for a reader that wants to show
        /// it.
        ///
        /// Traps past the amount width, which is a bound on how far a
        /// market can compound before its own index stops being
        /// readable.
        pub fn index_scaled(&self) -> u128 {
            started(self.index.get()).scaled().to_u128()
        }
    }

    /// The index a market starts at, which is one debt subunit per share.
    ///
    /// A cell that has never been written reads as zero, and zero is not
    /// a rate anything can be valued at — so the unwritten index is the
    /// identity rather than a state the bodies have to special-case
    /// individually.
    fn started(held: Fixed<Debt, Share>) -> Fixed<Debt, Share> {
        if held.is_zero() { Fixed::ONE } else { held }
    }
}
