//! A vault's balance is not writable: value moves, and a movement is
//! the only thing that changes it. The macro says so in a sentence, and
//! the type system says it again on its own terms — a vault leaf
//! satisfies no generic-write bound, so `set` has nothing to bind
//! against either way.
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        pub fn conjure(&mut self, holder: ResourceAddr) {
            self.till.at(holder).set(Quantity::from_subunits(1_000));
        }
    }
}

fn main() {}
