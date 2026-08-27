use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn file(&mut self, amount: Quantity) {
            self.log((amount, amount));
        }

        // Inlining binds each argument to its parameter's name, and a
        // pattern has no one name to bind.
        fn log(&mut self, (a, _b): (Quantity, Quantity)) {
            self.held.set(a);
        }
    }
}

fn main() {}
