use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    // The instantiation gate is the configuration's: a gate here reads
    // as guarding the state, and nothing reads it.
    #[state]
    #[requires(self)]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn touch(&mut self) {
            self.held.set(Quantity::ZERO);
        }
    }
}

fn main() {}
