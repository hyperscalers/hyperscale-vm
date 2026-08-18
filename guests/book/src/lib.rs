//! The order book, as one module: makers place asks into a declared
//! interval, takers fill by price-time priority within it.
//!
//! A price is quote subunits per base subunit, and it is an integer
//! because the order key is one: the key packs price over a sequence id,
//! so the ladder's ordering and its arithmetic are the same number. What
//! that costs is a price between two adjacent integers, which is a
//! modelling question — a tick index against a configured tick size — and
//! not one the arithmetic decides.
//!
//! A zero price is refused where an ask enters the book rather than where
//! a fill divides by it. The two are not the same check: an ask that
//! cannot be priced should never be standing, and refusing it at the fill
//! would leave it standing and unfillable.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod book {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{
        Bucket, Cell, Locked, Ordered, Quantity, Ratio, Rounding, Vault, fresh_id, pack,
    };

    /// The book's creation-fixed pair.
    struct Pair {
        base: Address,
        quote: Address,
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
        /// What makers escrow and takers buy.
        #[slot(1)]
        #[denomination(config.base)]
        base: Cell<Vault>,
        /// What takers pay and makers are owed.
        #[slot(1)]
        #[denomination(config.quote)]
        quote: Cell<Vault>,
        #[slot(3)]
        config: Locked<Pair>,
    }

    impl Book {
        /// Insert an ask at `price`, escrowing the maker's funds.
        #[name("place-ask")]
        pub fn place_ask(&mut self, price: u64, funds: Bucket) -> Result<(), Error> {
            if price == 0 {
                return Err(Error::UnpricedAsk);
            }
            // Price over a fresh sequence id: unique without reading the
            // book, which is what lets the entry key be declared.
            self.asks.at(pack(price, fresh_id())).set(funds.quantity());
            self.base.vault().put(funds);
            Ok(())
        }

        /// Buy base within the declared price interval, best price first.
        ///
        /// The interval is ordered by price over sequence id, so entry
        /// zero is always the best ask still standing — which is what
        /// makes price-time priority a walk from the front rather than a
        /// search.
        #[name("fill-asks")]
        pub fn fill_asks(&mut self, from: u64, to: u64, mut payment: Bucket) -> (Bucket, Bucket) {
            // The whole tiebreaker span at each end, so the interval covers
            // every sequence at the boundary prices.
            let mut asks = self.asks.range(pack(from, 0), pack(to, u64::MAX), 64);
            let mut budget = payment.quantity();
            let mut bought = Quantity::ZERO;

            while asks.count() > 0 {
                let price = asks.order(0) >> 64;
                // Standing asks are priced, because an unpriced one is
                // refused where it would have been placed.
                let Ok(per_unit) = Ratio::of(price, 1) else {
                    break;
                };
                let Ok(per_quote) = per_unit.recip() else {
                    break;
                };
                let available = asks.entry(0);
                // What the budget buys at this price, floored: a taker
                // gets whole base units and the remainder stays in the
                // change it walks away with.
                let take = available.min(budget.scale(per_quote, Rounding::Down));
                if take.is_zero() {
                    break;
                }
                // Exact by construction — the take was floored out of the
                // budget at this very price — so the direction decides
                // nothing and the fused multiply carries the product
                // whole regardless.
                budget -= take.scale(per_unit, Rounding::Down);
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
            let sold = self.base.vault().take(bought);
            let change = payment.take(budget);
            self.quote.vault().put(payment);
            (sold, change)
        }
    }
}
