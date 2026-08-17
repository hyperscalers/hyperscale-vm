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
//! # Shares retired rather than burned
//!
//! Returned shares go to a vault outside circulation and `supply` is
//! decremented, because the vocabulary can issue a resource and cannot
//! un-issue one. The accounting is the same; what differs is that the
//! retired units still exist somewhere a reader can point at.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod shares {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{
        Bucket, Cell, Locked, Quantity, Rounding, Vault, issue,
    };

    /// What the vault is denominated in.
    struct Settings {
        asset: Address,
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
        #[role(3)]
        config: Locked<Settings>,
        /// The assets under management.
        #[role(1)]
        #[denomination(config.asset)]
        assets: Cell<Vault>,
        /// Shares handed back, out of circulation.
        #[role(16)]
        #[denomination(issued(b""))]
        retired: Cell<Vault>,
        /// Shares in circulation. Kept here because the resource's own
        /// supply counts the retired ones too.
        #[role(17)]
        supply: Cell<Quantity>,
    }

    impl Shares {
        /// Hand over assets, take whatever shares they are worth.
        ///
        /// Down: the pool keeps the subunit, so assets per share does not
        /// fall.
        pub fn deposit(&mut self, funds: Bucket) -> Result<Bucket, Error> {
            let settings = self.config.locked();
            let mut vault = self.assets.vault();
            let assets = vault.get();
            let supply = self.supply.get();
            let paid = funds.quantity();
            vault.put(funds);

            // An unfunded pool prices a share at par, which is the only
            // rate that does not divide by nothing.
            let mut minted = paid;
            if !supply.is_zero() && !assets.is_zero() {
                let Ok(per_asset) = supply.ratio_to(assets) else {
                    return Err(Error::EmptyVault);
                };
                minted = paid.scale(per_asset, Rounding::Down);
            }
            self.supply.set(supply + minted);
            Ok(issue(b"", minted))
        }

        /// Ask for exactly `want` shares, paying out of `funds`.
        ///
        /// Up: the pool charges the subunit rather than absorbing it, so
        /// again assets per share does not fall. The change comes back.
        pub fn mint(&mut self, want: Quantity, mut funds: Bucket) -> Result<(Bucket, Bucket), Error> {
            let settings = self.config.locked();
            let mut vault = self.assets.vault();
            let assets = vault.get();
            let supply = self.supply.get();

            let mut needed = want;
            if !supply.is_zero() && !assets.is_zero() {
                let Ok(per_share) = assets.ratio_to(supply) else {
                    return Err(Error::EmptyVault);
                };
                needed = want.scale(per_share, Rounding::Up);
            }

            let Some(spare) = funds.quantity().try_sub(needed) else {
                return Err(Error::Insufficient);
            };
            // The change comes off before the rest goes in, so what the
            // vault keeps is what was charged.
            let change = funds.take(spare);
            vault.put(funds);
            self.supply.set(supply + want);
            Ok((issue(b"", want), change))
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
            let settings = self.config.locked();
            let mut vault = self.assets.vault();
            let assets = vault.get();
            let supply = self.supply.get();

            let Ok(per_asset) = supply.ratio_to(assets) else {
                return Err(Error::EmptyVault);
            };
            let needed = want.scale(per_asset, Rounding::Up);

            let Some(spare) = units.quantity().try_sub(needed) else {
                return Err(Error::Insufficient);
            };
            let back = units.take(spare);
            self.retired.vault().put(units);
            self.supply.set(supply - needed);
            Ok((vault.take(want), back))
        }

        /// Hand back shares, take whatever assets they are worth.
        ///
        /// Down: the pool keeps the subunit.
        pub fn redeem(&mut self, units: Bucket) -> Result<Bucket, Error> {
            let settings = self.config.locked();
            let mut vault = self.assets.vault();
            let assets = vault.get();
            let supply = self.supply.get();
            let returned = units.quantity();

            let Ok(per_share) = assets.ratio_to(supply) else {
                return Err(Error::EmptyVault);
            };
            let out = returned.scale(per_share, Rounding::Down);

            self.retired.vault().put(units);
            self.supply.set(supply - returned);
            Ok(vault.take(out))
        }
    }
}
