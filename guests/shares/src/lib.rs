//! The share vault: assets in, shares out, at whatever the pool is worth.
//!
//! Four ways in and out, because a vault that only offers two hides the
//! half of its rounding that goes the other way. `deposit` and `redeem`
//! are stated in what the caller *hands over*; `mint` and `withdraw` are
//! stated in what the caller *wants back*. The first pair rounds the
//! output down and the second rounds the input up, and both directions
//! are the same rule: the shared invariant — assets per share — never
//! falls, so whichever side the truncated subunit lands on, it lands on
//! the pool's.
//!
//! That is why "always round down" is wrong as a slogan and why the
//! vocabulary makes every one of the four say which way it went.
//!
//! # The donation route
//!
//! Rounding does not defend the first depositor. Rounding toward the
//! vault favours existing shareholders, and in the classic inflation
//! attack the existing shareholder *is* the attacker: deposit one
//! subunit, donate a fortune, and the next depositor's mint rounds to
//! nothing.
//!
//! What closes that route is the method set. Assets reach this instance
//! only through a body that takes a `Bucket`, and each of those bodies
//! mints where it credits, so a credit and a mint are one operation
//! rather than two a caller can order independently. There is no bare
//! transfer and so no donation. A bare-transfer path would need a
//! virtual-share offset or a burned minimum mint to stay safe.
//!
//! The argument is about the route value takes and not about what
//! travels it: it establishes that assets cannot arrive unaccompanied by
//! a mint, and says nothing about which resource arrives.
//!
//! # Returned shares are destroyed
//!
//! A share handed back is burned rather than parked: the units stop
//! existing and the shard's own supply falls with them, which is what a
//! redemption means. Parking them would leave the same arithmetic over a
//! balance nobody can spend — indistinguishable from a redemption to
//! anyone reading this contract, and a lie to anyone reading the shard's
//! supply.
//!
//! `supply` is still a cell here, because it is the *circulating* total
//! this vault prices against and a contract cannot read the shard's
//! accumulator. What changed is that the two now agree.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod shares {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity, Rounding, burn, mint};

    /// What the vault is denominated in.
    #[config]
    struct Settings {
        asset: ResourceAddr,
    }

    /// What an entry point declines with.
    #[error]
    enum Error {
        /// The pool holds nothing to price a share against.
        EmptyVault,
        /// What arrived does not cover what was asked for.
        Insufficient,
    }

    #[state]
    struct Shares {
        /// Shares in circulation, which is what a redemption is priced
        /// against.
        supply: Cell<Quantity>,
    }

    impl Shares {
        /// Hand over assets, take whatever shares they are worth.
        ///
        /// Down: the pool keeps the subunit, so assets per share does not
        /// fall.
        pub fn deposit(&mut self, funds: Bucket) -> Result<Bucket, Error> {
            let mut vault = self.vault(self.config().asset);
            let assets = vault.balance();
            let supply = self.supply.get();
            let paid = funds.quantity();
            vault.put(funds);

            // An unfunded pool prices a share at par, which is the only
            // rate that does not divide by nothing.
            let minted = if supply.is_zero() || assets.is_zero() {
                paid
            } else {
                let Ok(per_asset) = supply.ratio_to(assets) else {
                    return Err(Error::EmptyVault);
                };
                paid.scale(per_asset, Rounding::Down)
            };
            self.supply.set(supply + minted);
            Ok(mint(b"", minted))
        }

        /// Ask for exactly `want` shares, paying out of `funds`.
        ///
        /// Up: the pool charges the subunit rather than absorbing it, so
        /// again assets per share does not fall. The change comes back.
        pub fn mint(
            &mut self,
            want: Quantity,
            mut funds: Bucket,
        ) -> Result<(Bucket, Bucket), Error> {
            let mut vault = self.vault(self.config().asset);
            let assets = vault.balance();
            let supply = self.supply.get();

            let needed = if supply.is_zero() || assets.is_zero() {
                want
            } else {
                let Ok(per_share) = assets.ratio_to(supply) else {
                    return Err(Error::EmptyVault);
                };
                want.scale(per_share, Rounding::Up)
            };

            let Some(spare) = funds.quantity().try_sub(needed) else {
                return Err(Error::Insufficient);
            };
            // The change comes off before the rest goes in, so what the
            // vault keeps is what was charged.
            let change = funds.take(spare);
            vault.put(funds);
            self.supply.set(supply + want);
            Ok((mint(b"", want), change))
        }

        /// Ask for exactly `want` assets, paying in shares.
        ///
        /// Up on the shares taken: the pool retires the subunit rather
        /// than giving it away.
        pub fn withdraw(
            &mut self,
            want: Quantity,
            mut units: Bucket,
        ) -> Result<(Bucket, Bucket), Error> {
            let mut vault = self.vault(self.config().asset);
            let assets = vault.balance();
            let supply = self.supply.get();

            let Ok(per_asset) = supply.ratio_to(assets) else {
                return Err(Error::EmptyVault);
            };
            let needed = want.scale(per_asset, Rounding::Up);

            let Some(spare) = units.quantity().try_sub(needed) else {
                return Err(Error::Insufficient);
            };
            let back = units.take(spare);
            burn(b"", units);
            self.supply.set(supply - needed);
            Ok((vault.take(want), back))
        }

        /// Hand back shares, take whatever assets they are worth.
        ///
        /// Down: the pool keeps the subunit.
        pub fn redeem(&mut self, units: Bucket) -> Result<Bucket, Error> {
            let mut vault = self.vault(self.config().asset);
            let assets = vault.balance();
            let supply = self.supply.get();
            let returned = units.quantity();

            let Ok(per_share) = assets.ratio_to(supply) else {
                return Err(Error::EmptyVault);
            };
            let out = returned.scale(per_share, Rounding::Down);

            burn(b"", units);
            self.supply.set(supply - returned);
            Ok(vault.take(out))
        }
    }
}
