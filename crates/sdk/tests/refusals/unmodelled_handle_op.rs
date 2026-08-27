//! A method on a handle that names no operation.
//!
//! A handle reaches the kernel, so what a body does through one is what
//! the declaration has to carry. A method the vocabulary does not hold
//! is a body reaching for a capability nothing bought — refused where it
//! was written, rather than emitted and trapped at every call.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Quantity;

    #[state]
    struct Contract {}

    impl Contract {
        pub fn drain(&mut self, a: Address, amount: Quantity) {
            self.vault(a).siphon(amount);
        }
    }
}

fn main() {}
