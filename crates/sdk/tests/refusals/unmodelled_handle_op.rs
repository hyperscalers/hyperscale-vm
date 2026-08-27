//! A method on a handle that names no operation.
//!
//! A handle reaches the kernel, so what a body does through one is what
//! the declaration has to carry. A method the vocabulary does not hold
//! is a body reaching for a capability nothing bought — refused where it
//! was written, rather than emitted and trapped at every call.

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
        pub fn drain(&mut self, a: ResourceAddr, amount: Quantity) {
            self.till.at(a).siphon(amount);
        }
    }
}

fn main() {}
