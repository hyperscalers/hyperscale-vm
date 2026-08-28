use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        // A second `#[name]` would silently win; the first published name
        // vanishes.
        #[name("first-name")]
        #[name("second-name")]
        pub fn count(&self) -> u64 {
            1
        }
    }
}

fn main() {}
