use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // The name a method publishes is its own, spelled the way the
        // protocol spells every other published name. Saying it again is
        // a line that means nothing until the day it stops agreeing.
        #[name("set-fee")]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
