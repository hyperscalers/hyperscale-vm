//! The constant-product pool, as one module.
//!
//! Nothing here is written twice: the declaration routing reads, the WIT
//! world, the ABI binding and the executing component all come out of the
//! bodies below.
//!
//! The curve is written the way it denominates. `y * dx` is a product of
//! Y-units and X-units, which measures nothing and overflows for any pool
//! a real market reaches; `y * (dx / (x + dx))` is Y-units scaled by a
//! dimensionless share, which is what the pool actually pays out and
//! cannot overflow, because the share is bounded below one. The
//! vocabulary admits only the second, and the fused multiply behind it
//! holds the product whole so the output rounds once rather than twice.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod amm {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Cell, Locked, Quantity, Rounding, UnitFixed, Vault};

    /// The pool's creation-fixed configuration: the pair it trades and
    /// the fee it takes.
    ///
    /// The fee is bounded by its type rather than by the swap that reads
    /// it. A pool created with a fee above one is a pool that should not
    /// exist, and refusing every swap instead would leave it created,
    /// bricked, and holding funds.
    struct Settings {
        x: Address,
        y: Address,
        fee: UnitFixed,
    }

    /// What a swap declines with when the output misses its floor.
    ///
    /// A race the sender lost between signing and execution rather than
    /// a defect it committed, so it is declared rather than trapped.
    #[error]
    enum Error {
        SlippageExceeded,
        EmptyPool,
    }

    #[state]
    struct Amm {
        #[role(3)]
        config: Locked<Settings>,
        /// The side the pool buys.
        #[role(1)]
        #[denomination(config.x)]
        sold: Cell<Vault>,
        /// The side it sells.
        #[role(1)]
        #[denomination(config.y)]
        bought: Cell<Vault>,
    }

    impl Amm {
        /// Swap `input` against the pool, returning the bought side.
        pub fn swap(&mut self, input: Bucket, min_out: Quantity) -> Result<Bucket, Error> {
            // Pins the whole configuration record: the fee is read from
            // it, so the swap wants it stable, not merely consulted.
            let settings = self.config.locked();
            let mut sold = self.sold.vault();
            let mut bought = self.bought.vault();

            let x = sold.balance();
            let y = bought.balance();
            // The fee is the part of the payment the curve does not see,
            // and it is a real division of the edge rather than a number
            // beside it: the traded side is computed, the fee is the
            // remainder, and the two sum to what arrived because the
            // kernel performed the subtraction. The fee is named second,
            // so the truncated subunit stays with the pool.
            let (traded, fee) = input.split(settings.fee.complement().ratio());
            let dx = traded.quantity();

            // An empty pool has no share to quote, which is a refusal an
            // author can word rather than a division the machine traps
            // on.
            let Ok(share) = dx.ratio_to(x + dx) else {
                return Err(Error::EmptyPool);
            };
            // Down, which is what keeps the product of the reserves from
            // falling: the pool never pays out the subunit it rounded.
            let out = y.scale(share, Rounding::Down);

            // The payment goes in before the floor is judged, because a
            // body disposes of what it holds on every path it can leave
            // by — a refusal that let the input fall out of scope would
            // be dropping value, which the kernel refuses. A decline
            // discards the whole transaction, so the credit lands only on
            // the path that also takes the output.
            sold.put(traded);
            sold.put(fee);
            if out < min_out {
                return Err(Error::SlippageExceeded);
            }
            Ok(bought.take(out))
        }
    }
}
