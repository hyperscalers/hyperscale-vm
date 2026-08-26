use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    // A second struct would fold its fields into the same slot table
    // under the shared counter, unchecked against the module's name.
    #[state]
    struct Extra {
        hoard: Cell<Quantity>,
    }

    impl Contract {
        pub fn read(&self) -> Quantity {
            self.held.get()
        }
    }
}

fn main() {}
