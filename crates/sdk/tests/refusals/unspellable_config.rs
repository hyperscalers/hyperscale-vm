use hyperscale_vm_sdk::blueprint;

// A configuration value carries its own kind, so its field name is the
// one thing a consumer cannot recover from the leaf — and it is held to
// being a name for exactly that reason.
#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        président: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        pub fn settle(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
