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
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity, Rounding, UnitFixed};

    /// A claim on the pool, issued against what a provider put in.
    ///
    /// The pair sits in the protocol's vault cells, which name no owner
    /// but the instance — so a provider's stake is a resource they hold
    /// rather than a row this package keeps about them.
    #[resource(grants(mint = self, burn = self))]
    struct Share;

    /// The pool's creation-fixed configuration: the pair it trades and
    /// the fee it takes.
    ///
    /// The fee is bounded by its type rather than by the swap that reads
    /// it. A pool created with a fee above one is a pool that should not
    /// exist, and refusing every swap instead would leave it created,
    /// bricked, and holding funds.
    #[config]
    struct Settings {
        x: ResourceAddr,
        y: ResourceAddr,
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
        /// The deposit is too small to be worth a subunit of the pool.
        ///
        /// Refused rather than minted at zero, because a provider who
        /// funds the pool and receives nothing has made a donation they
        /// did not offer.
        NothingMinted,
    }

    /// The pair itself sits in the protocol's own vault cells, which
    /// every owner has. What the pool keeps of its own is the count of
    /// claims outstanding against them.
    #[state]
    struct Amm {
        /// Shares in circulation, which is what a provider's stake is
        /// priced against.
        ///
        /// The circulating total rather than the shard's accumulator: a
        /// contract cannot read the latter, and a burn on redemption
        /// keeps the two agreeing.
        supply: Cell<Quantity>,
    }

    impl Amm {
        /// Swap `input` against the pool, returning the bought side.
        pub fn swap(&mut self, input: Bucket, min_out: Quantity) -> Result<Bucket, Error> {
            let settings = self.config();
            // The direction is carried by the edge that arrives: a bucket
            // knows its own resource, so the pool sells the side it was
            // paid in and pays out of the other. The pair is stated once,
            // in the configuration, and the two-cycle over it is the
            // package's own — held in the declaration a caller routes on
            // rather than in a value a caller supplies.
            //
            // Both sides are read off the configuration rather than off
            // the edge, and that is what keeps the cycle total. A pool
            // that sold whatever arrived would take a resource in neither
            // side, open a vault holding none of it, and quote a share
            // against an empty reserve — so the declared denomination is
            // the configured side, and a third resource is refused at
            // admission rather than priced against nothing.
            let paid = input.resource();
            let sells_x = paid == settings.x;
            let sold_side = if sells_x { settings.x } else { settings.y };
            let bought_side = if sells_x { settings.y } else { settings.x };
            let mut sold = self.vault(sold_side);
            let mut bought = self.vault(bought_side);

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

            if out < min_out {
                return Err(Error::SlippageExceeded);
            }
            sold.put(traded);
            sold.put(fee);
            Ok(bought.take(out))
        }

        /// Fund both sides, take a claim on the pool.
        ///
        /// The first provider prices the pool: nothing else can, so the
        /// mint is the geometric mean of what arrived — the product held
        /// whole, because for any pool a real market reaches `dx * dy`
        /// leaves the amount width while its root does not.
        ///
        /// Every provider after that is priced against the pool as it
        /// stands, and against the *lesser* of the two claims they could
        /// argue for. That is what makes a skewed deposit unprofitable
        /// rather than dilutive: the side deposited in excess is bought
        /// at no better a rate than the side deposited short, and the
        /// remainder stays where it landed, which is with every existing
        /// provider including the depositor.
        pub fn add_liquidity(&mut self, x_side: Bucket, y_side: Bucket) -> Result<Bucket, Error> {
            let settings = self.config();
            let mut vault_x = self.vault(settings.x);
            let mut vault_y = self.vault(settings.y);

            // Both reserves are read before either deposit lands: what
            // a claim is priced against is the pool the provider is
            // joining, not the one they have already changed.
            let x = vault_x.balance();
            let y = vault_y.balance();
            let dx = x_side.quantity();
            let dy = y_side.quantity();
            let supply = self.supply.get();

            let minted = if supply.is_zero() {
                dx.geometric_mean(dy)
            } else {
                // Against an outstanding supply the reserves cannot be
                // empty, so the two ratios are the pool's own and the
                // refusal is unreachable rather than tolerated.
                let Ok(share_x) = dx.ratio_to(x) else {
                    return Err(Error::EmptyPool);
                };
                let Ok(share_y) = dy.ratio_to(y) else {
                    return Err(Error::EmptyPool);
                };
                let claim_x = supply.scale(share_x, Rounding::Down);
                let claim_y = supply.scale(share_y, Rounding::Down);
                claim_x.min(claim_y)
            };

            if minted.is_zero() {
                return Err(Error::NothingMinted);
            }

            vault_x.put(x_side);
            vault_y.put(y_side);
            self.supply.set(supply + minted);
            Ok(Share::mint(minted))
        }

        /// Hand back a claim, take a share of both sides.
        ///
        /// Down on both, so the truncated subunit stays with the pool:
        /// what a share is worth never falls because somebody left.
        pub fn remove_liquidity(&mut self, shares: Bucket) -> Result<(Bucket, Bucket), Error> {
            let settings = self.config();
            let mut vault_x = self.vault(settings.x);
            let mut vault_y = self.vault(settings.y);

            let x = vault_x.balance();
            let y = vault_y.balance();
            let supply = self.supply.get();
            let returned = shares.quantity();

            // Nothing is disposed of before this, and nothing needs to
            // be: a refusal commits nothing, so the claim the caller
            // handed over goes back with the rest of the transaction.
            let Ok(part) = returned.ratio_to(supply) else {
                return Err(Error::EmptyPool);
            };
            let out_x = x.scale(part, Rounding::Down);
            let out_y = y.scale(part, Rounding::Down);

            // Burned rather than parked: the units stop existing and the
            // shard's supply falls with them, which is what handing a
            // claim back means. Parking would leave the same arithmetic
            // over a balance nobody can spend.
            Share::burn(shares);
            self.supply.set(supply - returned);
            Ok((vault_x.take(out_x), vault_y.take(out_y)))
        }

        /// Whether the pool trades `resource` at all.
        ///
        /// What a router asks before sending a swap here, and what a
        /// swap itself never asks: the pair is in the address, so a
        /// third resource is refused at admission rather than answered.
        pub fn trades(&self, resource: ResourceAddr) -> bool {
            is_side(self.config(), resource)
        }
    }

    /// Whether `resource` is one of the configured pair.
    ///
    /// Over the record whole rather than over its fields, which is what
    /// a helper is for — and what crosses is the fields the kernel
    /// evaluated, assembled under the name the package gave them.
    fn is_side(settings: Settings, resource: ResourceAddr) -> bool {
        resource == settings.x || resource == settings.y
    }
}
