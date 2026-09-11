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
            self.poll().into()
        }

        // A helper that exits early hands its result through a binding
        // typed at its return type, and `impl Trait` cannot type one.
        fn poll(&self) -> impl Into<Quantity> {
            if self.held.get().is_zero() {
                return Quantity::ZERO;
            }
            self.held.get()
        }
    }
}

fn main() {}
