use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn read(&self) -> Quantity {
            self.held.get()
        }

        // `self.holdings(..)` in any body is the vocabulary's accessor;
        // a private method under the name would shadow it at every call.
        fn holdings(&self) -> Quantity {
            Quantity::ZERO
        }
    }
}

fn main() {}
