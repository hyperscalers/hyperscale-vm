use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn drain(&mut self) -> Quantity {
            self.poll()
        }

        // A helper yields its tail: spliced into `drain`, this `return`
        // would return from the export.
        fn poll(&self) -> Quantity {
            if self.held.get().is_zero() {
                return Quantity::ZERO;
            }
            self.held.get()
        }
    }
}

fn main() {}
