//! A loan that lasts one transaction, and the obligation that makes it
//! safe.
//!
//! The pool lends without collateral and without asking who is
//! borrowing, which is only sound if the loan cannot outlive the
//! transaction that took it. Every flash lender on every other platform
//! establishes that by *checking* — the pool reads its own balance after
//! the callback and reverts if it fell — and the check is the whole
//! design: it has to be written, it has to be right, and a lender that
//! forgets it is drained by the first borrower who notices.
//!
//! Here the obligation is a value instead. `draw` mints one `Debt`
//! subunit per subunit lent and hands it out beside the loan, and `Debt`
//! grants `deposit = nobody` — no vault may hold it, anywhere, under any
//! owner. So the borrower has exactly two things they can do with it:
//! give it back to `repay`, which burns it, or fail to, and a bucket
//! nobody consumed is a graph admission refuses. There is no balance
//! check in this contract and no callback for one to sit after, because
//! the property is carried by the resource rather than asserted by the
//! lender.
//!
//! What that costs is stated plainly: `Debt` is not composable with
//! anything. It cannot be pooled, wrapped, held overnight or sold, which
//! for an obligation is the point and for anything else would be the
//! closed-loop outcome under another name.
//!
//! # What this deliberately is not
//!
//! There is no fee. A fee is arithmetic over two resources and a policy
//! about where it accrues, and neither says anything about the property
//! this package exists to demonstrate. A real lender charges one, and
//! charges it in `repay`.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod flashloan {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    /// The obligation a borrower carries for the length of one
    /// transaction: one subunit per subunit lent.
    ///
    /// Whole units, because an obligation is counted rather than priced.
    #[resource(grants(mint = self, burn = self, deposit = nobody), display_digits = 0)]
    struct Debt;

    /// What the pool lends.
    #[config]
    struct Terms {
        asset: ResourceAddr,
    }

    /// What an entry point declines with.
    #[error]
    enum Error {
        /// Less came back than was owed.
        Short,
    }

    impl Flashloan {
        /// Lend `amount`, and mint the obligation to give it back.
        ///
        /// The two leave together and nothing binds them but the
        /// borrower's need to be rid of the second, which is what makes
        /// the loan's route through the transaction entirely theirs: it
        /// can be swapped, split, lent on, and arrive back from anywhere.
        pub fn draw(&mut self, amount: Quantity) -> (Bucket, Bucket) {
            let funds = self.vault(self.config().asset).take(amount);
            (funds, Debt::mint(amount))
        }

        /// Take the loan back and retire the obligation.
        ///
        /// The obligation is measured against what arrives rather than
        /// against anything remembered, so a partial repayment is an
        /// ordinary call with a smaller `debt` beside it and the rest is
        /// still outstanding — held as a bucket that has to reach one of
        /// these before the transaction can be admitted.
        pub fn repay(&mut self, funds: Bucket, debt: Bucket) -> Result<(), Error> {
            let returned = funds.quantity();
            let owed = debt.quantity();
            if returned.try_sub(owed).is_none() {
                return Err(Error::Short);
            }
            self.vault(self.config().asset).put(funds);
            Debt::burn(debt);
            Ok(())
        }
    }
}
