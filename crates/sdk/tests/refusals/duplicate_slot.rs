use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        // A second `#[slot]` would silently win; the first pin vanishes.
        #[slot(20)]
        #[slot(30)]
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn count(&self) -> u64 {
            1
        }
    }
}

fn main() {}
