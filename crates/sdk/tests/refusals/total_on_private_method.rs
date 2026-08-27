use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        // A private method publishes nothing, so the mark would vanish
        // with the export the author thought they were describing.
        #[total]
        fn tally(&mut self) {
            self.held.set(Quantity::ZERO);
        }
    }
}

fn main() {}
