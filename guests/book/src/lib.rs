//! The order book, as one module: makers place asks into a declared
//! interval, takers fill by price-time priority within it.
//!
//! Checked arithmetic throughout — an overflow is a deterministic trap
//! rather than a wrap, which release-mode arithmetic would otherwise give
//! it.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod book {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Keyed, Locked, Ordered, fresh_id, pack};

    /// The book's creation-fixed pair.
    struct Pair {
        base: Address,
        quote: Address,
    }

    #[state]
    struct Book {
        #[role(16)]
        asks: Ordered<u128>,
        #[role(1)]
        vaults: Keyed<Amount>,
        #[role(3)]
        config: Locked<Pair>,
    }

    impl Book {
        /// Insert an ask at `price`, escrowing the maker's funds.
        #[name("place-ask")]
        pub fn place_ask(&mut self, price: u64, funds: Bucket) {
            // Price over a fresh sequence id: unique without reading the
            // book, which is what lets the entry key be declared.
            self.asks.at(pack(price, fresh_id())).set(funds.amount());
            self.vaults.at(funds.resource()).put(funds);
        }

        /// Buy base within the declared price interval, best price first.
        ///
        /// The interval is ordered by price over sequence id, so entry
        /// zero is always the best ask still standing — which is what
        /// makes price-time priority a walk from the front rather than a
        /// search.
        #[name("fill-asks")]
        pub fn fill_asks(&mut self, from: u64, to: u64, payment: Bucket) -> (Bucket, Bucket) {
            // The whole tiebreaker span at each end, so the interval covers
            // every sequence at the boundary prices.
            let mut asks = self.asks.range(pack(from, 0), pack(to, u64::MAX), 64);
            let opening = payment.amount();
            let mut budget = opening;
            let mut bought: Amount = 0;

            while asks.count() > 0 {
                let price = asks.order(0) >> 64;
                assert!(price > 0, "zero-priced ask");
                let available = asks.entry(0);
                let take = available.min(budget / price);
                if take == 0 {
                    break;
                }
                budget -= take.checked_mul(price).unwrap();
                bought = bought.checked_add(take).unwrap();
                if take == available {
                    asks.remove(0);
                } else {
                    asks.set(0, available - take);
                }
            }

            // Note the config fields are read without pinning the leaf:
            // configuration is locked state, consultable without a claim.
            // The base the taker bought leaves the pool's own vault; the
            // whole payment goes into the other and the change comes back
            // out, so what the vault keeps is what was spent and the
            // taker's change is the value it arrived with — never a
            // number this body wrote down.
            let sold = self.vaults.at(self.config.base).take(bought);
            let mut proceeds = self.vaults.at(payment.resource());
            proceeds.put(payment);
            (sold, proceeds.take(budget))
        }
    }
}
