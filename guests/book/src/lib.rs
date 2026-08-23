//! The order book, as one module: makers place asks into a declared
//! interval, takers fill by price-time priority within it.
//!
//! A price is a count of ticks, and the tick is what the book was created
//! over. The key packs that count over a sequence id, so the ladder's
//! ordering stays an exact integer one however fine the tick is — which
//! is the whole reason an exchange quotes in ticks rather than in the
//! quote asset directly.
//!
//! What that buys is a price between two adjacent integers. A tick of
//! half a quote subunit prices an ask at three ticks at one and a half,
//! which no integer price can name, and the ladder is still walked by
//! comparing two `u64`s.
//!
//! The tick is a dimension of its own rather than a number beside the
//! price, and that is load-bearing: the configured size is quote per
//! *tick*, an ask states ticks per *base*, and composing the two cancels
//! the tick and leaves quote per base. The middle term goes away because
//! the types say it does, not because this body multiplied in the right
//! order.
//!
//! A zero price is refused where an ask enters the book rather than where
//! a fill divides by it. The two are not the same check: an ask that
//! cannot be priced should never be standing, and refusing it at the fill
//! would leave it standing and unfillable.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod book {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{
        Bucket, Fixed, Ordered, Quantity, Rate, Rounding, fresh_id, pack,
    };

    /// What the book sells.
    pub struct Base;
    /// What it is paid in.
    pub struct Quote;
    /// The step a price moves in. A dimension because the configured size
    /// and an ask's count are rates *through* it, and what cancels when
    /// they compose is the reason either is right.
    pub struct Tick;

    /// The book's creation-fixed pair and the step it quotes in.
    #[config]
    struct Pair {
        base: ResourceAddr,
        quote: ResourceAddr,
        /// What one tick is worth, in quote subunits.
        ///
        /// Fixed at creation because a book that could restep itself
        /// would reprice every ask standing in it.
        tick: Fixed<Quote, Tick>,
    }

    /// What placing an ask declines with.
    #[error]
    enum Error {
        UnpricedAsk,
    }

    #[state]
    struct Book {
        /// The standing ladder: a quantity of base per entry, which is a
        /// number the book records rather than value it holds.
        asks: Ordered<Quantity>,
    }

    impl Book {
        /// Insert an ask at `ticks` per base unit, escrowing the maker's
        /// funds.
        pub fn place_ask(&mut self, ticks: u64, funds: Bucket) -> Result<(), Error> {
            if ticks == 0 {
                return Err(Error::UnpricedAsk);
            }
            // The tick count over a fresh sequence id: unique without
            // reading the book, which is what lets the entry key be
            // declared.
            self.asks.at(pack(ticks, fresh_id())).set(funds.quantity());
            self.vault(self.config().base).put(funds);
            Ok(())
        }

        /// Buy base within the declared tick interval, best price first.
        ///
        /// The interval is ordered by tick count over sequence id, so
        /// entry zero is always the best ask still standing — which is
        /// what makes price-time priority a walk from the front rather
        /// than a search.
        pub fn fill_asks(&mut self, from: u64, to: u64, mut payment: Bucket) -> (Bucket, Bucket) {
            let tick = self.config().tick;
            // The whole tiebreaker span at each end, so the interval covers
            // every sequence at the boundary counts.
            let mut asks = self.asks.range(pack(from, 0), pack(to, u64::MAX), 64);
            let mut budget = payment.quantity();
            let mut bought = Quantity::ZERO;

            while asks.count() > 0 {
                // What this ask asks, in ticks for every base unit. A rate
                // against a unit rather than a quotient of two amounts,
                // so there is no denominator to refuse — which is what a
                // standing ask is: a count, per one.
                let ticks_per_base =
                    Rate::<Tick, Base>::per_unit(u128::from(asks.order(0).primary()));
                // Quote per tick through tick per base is quote per base,
                // and the tick cancels because the types cancel it.
                let per_unit = tick.rate().compose(ticks_per_base);
                let Ok(per_quote) = per_unit.recip() else {
                    break;
                };
                let available = asks.entry(0);
                // What the budget buys at this price, floored: a taker
                // gets whole base units and the remainder stays in the
                // change it walks away with.
                let take = available.min(budget.convert(per_quote, Rounding::Down));
                if take.is_zero() {
                    break;
                }
                // Rounded up, so a partial tick is paid for rather than
                // taken: the taker never gets base it did not cover.
                budget -= take.convert(per_unit, Rounding::Up);
                bought += take;
                if take == available {
                    asks.remove(0);
                } else {
                    asks.set(0, available - take);
                }
            }

            // The base the taker bought leaves the book's own vault, and
            // the change comes off the payment before the rest of it goes
            // in — so what the vault keeps is what was spent, and neither
            // half is a number this body wrote down.
            let sold = self.vault(self.config().base).take(bought);
            let change = payment.take(budget);
            self.vault(self.config().quote).put(payment);
            (sold, change)
        }
    }
}
