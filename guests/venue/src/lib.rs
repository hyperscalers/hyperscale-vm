//! The pass sold at the door: authority issued only on a condition the
//! issuer checks.
//!
//! A `#[proves(self)]` body is ordinary and may decline, so the price
//! of the door's proof lives in the proving call's own admission unit —
//! the payment is the proving method's parameter, and a proof without
//! one is not a composition anybody can spell. A short payment declines
//! the transaction wholesale, so nothing gated on the proof ever ran
//! without it.
//!
//! Two instances make the pattern whole: a door that sells its proof,
//! and a hall whose gate names that door. A component's address derives
//! from its configuration, so an instance cannot name itself in a gate
//! — authority earned conditionally is spent where somebody else's
//! configuration names the earner, exactly as an oracle's say-so is.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod venue {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity, Vault};
    use hyperscale_vm_sdk::{Address, ResourceAddr};

    /// What entry costs, and whose pass admits, fixed at creation.
    #[config]
    struct Terms {
        /// What the door is paid in.
        asset: ResourceAddr,
        /// The price of one pass, in subunits of it.
        price: u128,
        /// The door whose pass this instance's `enter` admits — another
        /// instance of this same package, named by address.
        door: Address,
    }

    /// What the door declines with.
    #[error]
    enum Error {
        /// The payment does not cover the price.
        Short,
    }

    #[state]
    struct Venue {
        /// What the passes were paid with.
        #[holds(config.asset)]
        till: Vault,
        /// How many entries this instance has admitted.
        admitted: Cell<u64>,
    }

    impl Venue {
        /// Prove this venue to whoever pays its price: the pass.
        ///
        /// The payment is banked and the claim is the call's one
        /// product; a payment short of the price declines, and the
        /// decline fails the whole transaction — which is what keeps
        /// anything gated on the pass from running unpaid.
        #[proves(self)]
        pub fn pass(&mut self, payment: Bucket) -> Result<(), Error> {
            if payment.quantity() < Quantity::from_subunits(self.config().price) {
                return Err(Error::Short);
            }
            self.till.put(payment);
            Ok(())
        }

        /// Behind the door: only a claim on the configured door admits,
        /// and the door's pass is the one call that mints one. The
        /// answer is this entrant's number.
        #[requires(config.door)]
        pub fn enter(&mut self) -> u64 {
            let count = self.admitted.get() + 1;
            self.admitted.set(count);
            count
        }
    }
}
