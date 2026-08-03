//! The question this spike was opened to answer: can a body written as
//! ordinary Rust yield the declaration, with no separate declaration
//! written by hand?
//!
//! Same bar as `stdlib_parity`, one level higher up. There the declarations
//! were written against the builder API and compared to the authored
//! fixtures. Here nobody writes a declaration at all — the contracts below
//! are contracts, and `#[blueprint]` derives the metadata from their
//! bodies. The comparison is still whole-structure equality against
//! `vm-effects::stdlib`.
//!
//! Everything that survives is therefore true of the derived form too: the
//! fixtures are routed under test elsewhere in the workspace, and these
//! packages are byte-identical to them.

// The contracts below are read by `#[blueprint]`, never called: what these
// tests exercise is the metadata derived from the bodies, and the derivation
// runs at expansion time. In a real contract crate the module is public and
// its methods are the package's exported surface, so nothing is dead there —
// the appearance is an artifact of a contract living inside a test binary.
#![allow(dead_code)]
// `&mut self` is the contract's own statement that a method mutates
// component state. That the host-side stub handles in `sdk::state` happen to
// take `&self` is an artifact of their being unimplemented off-guest, not a
// reason to narrow a contract's signature.
#![allow(clippy::needless_pass_by_ref_mut)]

use hyperscale_vm_effects::stdlib::{account_metadata, amm_metadata, book_metadata};
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod account {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Cell, Keyed};

    #[state]
    struct Account {
        #[role(1)]
        vaults: Keyed<Amount>,
        #[role(2)]
        claims: Keyed<Amount>,
        #[role(5)]
        entropy: Cell<u64>,
    }

    impl Account {
        /// Reserve `amount` on the caller's vault for `resource`.
        pub fn withdraw(&mut self, resource: Address, amount: u128) -> Bucket {
            self.vaults.at(resource).reserve(amount)
        }

        /// Credit the vault and the guaranteed-delivery cell beside it.
        pub fn deposit(&mut self, funds: Bucket) {
            self.vaults.at(funds.resource()).add(funds.amount());
            self.claims.at(funds.resource()).add(0);
        }

        /// Refuse unless the pinned balance covers `min`, touching nothing.
        #[name("assert-balance")]
        pub fn assert_balance(&mut self, resource: Address, min: u128, window: u64) {
            let balance = self.vaults.at(resource).pinned(window);
            assert!(balance >= min, "balance below the declared floor");
        }

        /// Stamp the transaction's randomness draw into the entropy leaf.
        #[name("stamp-entropy")]
        pub fn stamp_entropy(&mut self) {
            self.entropy.set(0);
        }
    }
}

#[blueprint]
mod amm {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Keyed, Locked};

    struct Settings {
        x: Address,
        y: Address,
        fee_bps: u64,
    }

    #[state]
    struct Amm {
        #[role(3)]
        config: Locked<Settings>,
        #[role(1)]
        vaults: Keyed<Amount>,
    }

    impl Amm {
        /// Swap `input` against the pool, returning the bought side.
        pub fn swap(&mut self, input: Bucket, min_out: u128) -> Bucket {
            // Pins the whole configuration record: the fee is read from it,
            // so the swap wants it stable, not merely consulted.
            let settings = self.config.locked();
            let mut sold = self.vaults.at(settings.x);
            let mut bought = self.vaults.at(settings.y);

            let x = sold.get();
            let y = bought.get();
            let dx = input.amount() * u128::from(10_000 - settings.fee_bps) / 10_000;
            let out = y * dx / (x + dx);
            assert!(out >= min_out, "output below the declared floor");

            sold.set(x + input.amount());
            bought.set(y - out);
            Bucket::of(settings.y, out)
        }
    }
}

#[blueprint]
mod book {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Keyed, Locked, Ordered, fresh_id, pack};

    struct Pair {
        base: Address,
        quote: Address,
    }

    #[state]
    struct Book {
        #[role(4)]
        asks: Ordered<u128>,
        #[role(1)]
        vaults: Keyed<Amount>,
        #[role(3)]
        config: Locked<Pair>,
    }

    impl Book {
        /// Insert an ask at `price`, escrowing the maker's funds.
        pub fn place_ask(&mut self, price: u64, funds: Bucket) {
            // Price over a fresh sequence id: unique without reading the
            // book, which is what lets the entry key be declared.
            self.asks.at(pack(price, fresh_id())).set(funds.amount());
            self.vaults.at(funds.resource()).add(funds.amount());
        }

        /// Buy base within the declared price interval, best price first.
        pub fn fill_asks(&mut self, from: u64, to: u64, payment: Bucket) -> (Bucket, Bucket) {
            // The whole tiebreaker span at each end, so the interval covers
            // every sequence at the boundary prices.
            let mut asks = self.asks.range(pack(from, 0), pack(to, u64::MAX), 64);
            let mut bought = 0;
            let mut spent = 0;

            let mut index = 0;
            while index < asks.count() {
                let size = asks.entry(index);
                bought += size;
                spent += size;
                asks.remove(index);
                index += 1;
            }

            // Note the config fields are read without pinning the leaf:
            // configuration is locked state, consultable without a claim.
            self.vaults.at(self.config.base).sub(bought);
            self.vaults.at(payment.resource()).add(spent);

            (
                Bucket::of(self.config.base, bought),
                Bucket::of(payment.resource(), payment.amount() - spent),
            )
        }
    }
}

#[test]
fn the_account_body_derives_its_authored_signature() {
    assert_eq!(account::blueprint().metadata(), account_metadata());
}

#[test]
fn the_pool_body_derives_its_authored_signature() {
    assert_eq!(amm::blueprint().metadata(), amm_metadata());
}

#[test]
fn the_book_body_derives_its_authored_signature() {
    assert_eq!(book::blueprint().metadata(), book_metadata());
}
