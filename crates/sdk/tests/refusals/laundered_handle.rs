//! A handle handed to something the walk does not model.
//!
//! The walk tracks a handle only while it can see it. A free call, a
//! clone, an identity function — anything it does not model — would
//! hand the handle back as an opaque value, and an operation through
//! that value would reach the kernel with nothing declared for it.
//! Refused where the handle leaves the walk's sight.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Keyed, Vault};

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        pub fn drain(&mut self, a: ResourceAddr, b: ResourceAddr, c: ResourceAddr) {
            let wrapped = self.till.at(a);
            let _ = Some(wrapped).unwrap().balance();

            let borrowed = self.till.at(b);
            let _ = Clone::clone(&borrowed).balance();

            let passed = self.till.at(c);
            let _ = core::convert::identity(passed).balance();
        }
    }
}

fn main() {}
