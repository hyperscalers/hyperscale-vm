//! The fee splitter: revenue in, three configured shares out.
//!
//! Two ways to divide, because a splitter that offers one hides what it
//! does with the part that will not divide. `disburse` keeps the
//! truncated subunit, which is what a revenue share wants — the parties
//! are paid, the dust accumulates, and nothing is refused over a subunit.
//! `settle` refuses instead, which is what a schedule that must add up
//! wants: a treasury allocation or a drop against a published table is
//! wrong if it pays out anything other than the whole.
//!
//! Both divide the *whole* by each share, so the parts do not depend on
//! the order they are taken in, and both hand back the remainder rather
//! than folding it into the last party. Folding would quietly make the
//! last-named party the residual claimant, which is a policy nobody
//! wrote down.
//!
//! # The dust has to go somewhere
//!
//! A part of a payment that no share claimed is still value, and the
//! kernel refuses a body that drops one. That is the whole reason the
//! remainder is a named thing here rather than an implementation detail:
//! the vocabulary makes disposing of it a decision the author states.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod payouts {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Quantity, Ratio, Rounding, UnitFixed, Vault};

    /// Who takes what, fixed when the splitter is created.
    ///
    /// The shares are bounded by their type rather than checked here: a
    /// splitter created with a share above one is one that should not
    /// exist, and refusing every payment instead would leave it created
    /// and holding funds.
    #[config]
    struct Terms {
        /// What this splitter divides. A payment in anything else is
        /// refused where the parameter is judged, not here.
        asset: ResourceAddr,
        /// The share the protocol takes.
        protocol: UnitFixed,
        /// The share the treasury takes.
        treasury: UnitFixed,
        /// The share the referrer takes.
        referrer: UnitFixed,
    }

    /// What a division declines with.
    #[error]
    enum Error {
        /// The shares did not claim the whole payment.
        ///
        /// Only `settle` raises it: `disburse` keeps what is left over
        /// rather than refusing it.
        ShareUnclaimed,
        /// The payment is too small to pay a whole lot of.
        BelowOneLot,
    }

    #[state]
    struct Payouts {
        /// Where the dust lands, joining the next payment.
        #[holds(config.asset)]
        kept: Vault,
    }

    impl Payouts {
        /// Divide a payment three ways and keep what will not divide.
        ///
        /// The dust lands in the splitter's own vault, where it joins the
        /// next payment: over many payments the parties are paid the
        /// shares they were promised, and no single payment is refused
        /// for being indivisible.
        #[allow(clippy::tuple_array_conversions)] // the lowering follows these names to the edges
        pub fn disburse(&mut self, pot: Bucket) -> (Bucket, Bucket, Bucket) {
            let terms = self.config();

            // One division against the whole table rather than three
            // takes in sequence: a second share of what a first share
            // left is a share of a different number, so taking in order
            // would quietly make the order part of the policy.
            let ([protocol, treasury, referrer], dust) = pot.split_n(&[
                terms.protocol.ratio(),
                terms.treasury.ratio(),
                terms.referrer.ratio(),
            ]);
            self.kept.put(dust);
            (protocol, treasury, referrer)
        }

        /// Divide a payment three ways, or refuse it.
        ///
        /// For a schedule that has to add up: a remainder means the
        /// payment and the table disagree, and paying out three parts
        /// that do not sum to what arrived is worse than declining.
        #[allow(clippy::tuple_array_conversions)] // the lowering follows these names to the edges
        pub fn settle(&mut self, pot: Bucket) -> Result<(Bucket, Bucket, Bucket), Error> {
            let terms = self.config();

            let ([protocol, treasury, referrer], dust) = pot.split_n(&[
                terms.protocol.ratio(),
                terms.treasury.ratio(),
                terms.referrer.ratio(),
            ]);

            // The parts are still in hand on the refusing path, and that
            // is the whole of what happens to them: a decline discards
            // the transaction, so an edge nobody routed goes back where it
            // came from with everything else the transaction claimed.
            if !dust.quantity().is_zero() {
                return Err(Error::ShareUnclaimed);
            }
            self.kept.put(dust);
            Ok((protocol, treasury, referrer))
        }

        /// Pay out in whole lots only, and hand back what is short of one.
        ///
        /// What a payer wants where the receiving side prices in lots
        /// rather than subunits: the payment is rounded down to a whole
        /// multiple of the configured lot and the change goes back,
        /// rather than being kept as dust nobody agreed to leave.
        ///
        /// Both halves go back to the caller, so this reaches no cell and
        /// denominates nothing — what a payer sends is theirs to name.
        /// `disburse` and `settle` take the configured asset because they
        /// credit the vault the configuration keys; a method that keeps
        /// none of what passes through it has no such claim to make.
        pub fn in_lots(&mut self, pot: Bucket, lot: Quantity) -> Result<(Bucket, Bucket), Error> {
            let paid = pot.quantity();
            // A lot of nothing is not a lot, and rounding to a multiple
            // of it is the identity — so a caller naming one would be
            // paid in full by a method whose whole job is to round. It
            // meets the same refusal a payment short of one lot does,
            // which is what `divides` already says about a zero step.
            let whole = paid.round_to_multiple(lot, Rounding::Down);
            if lot.is_zero() || whole.is_zero() {
                return Err(Error::BelowOneLot);
            }

            // The payable part as a share of what arrived, which is exact
            // because both terms are subunits of the same payment. Past
            // the guard the payment is non-zero, so the ratio is there.
            let share = whole.ratio_to(paid).unwrap_or(Ratio::ONE);
            // What is left is short of a lot by construction, so the
            // change is exact rather than approximate.
            let (payable, change) = pot.split(share);
            Ok((payable, change))
        }

        /// Whether a payment divides into whole lots with nothing over.
        ///
        /// What a payer asks before sending. A lot of nothing divides
        /// nothing, which is the same answer `in_lots` gives it.
        pub fn divides(&self, paid: Quantity, lot: Quantity) -> bool {
            paid.is_multiple_of(lot)
        }
    }
}
