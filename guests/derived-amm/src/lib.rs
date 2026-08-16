//! The constant-product pool, as one module.
//!
//! Nothing here is written twice: the declaration routing reads, the WIT
//! world, the ABI binding and the executing component all come out of the
//! bodies below.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod amm {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Keyed, Locked};

    /// The pool's creation-fixed configuration: the pair it trades and
    /// the fee it takes.
    struct Settings {
        x: Address,
        y: Address,
        fee_bps: u64,
    }

    /// What a swap declines with when the output misses its floor.
    ///
    /// A race the sender lost between signing and execution rather than
    /// a defect it committed, so it is declared rather than trapped.
    #[error]
    enum Error {
        SlippageExceeded,
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
        pub fn swap(&mut self, input: Bucket, min_out: u128) -> Result<Bucket, Error> {
            // Pins the whole configuration record: the fee is read from it,
            // so the swap wants it stable, not merely consulted.
            let settings = self.config.locked();
            let mut sold = self.vaults.at(settings.x);
            let mut bought = self.vaults.at(settings.y);

            let x = sold.get();
            let y = bought.get();
            let dx = input.amount() * u128::from(10_000 - settings.fee_bps) / 10_000;
            let out = y * dx / (x + dx);
            if out < min_out {
                return Err(Error::SlippageExceeded);
            }

            sold.set(x + input.amount());
            bought.set(y - out);
            Ok(Bucket::of(settings.y, out))
        }
    }
}
