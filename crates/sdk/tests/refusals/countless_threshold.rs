use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        chair: Address,
        deputy: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // A threshold's count is a literal the macro reads, not a claim:
        // what it counts comes after it.
        #[requires(n_of(config.chair, config.deputy))]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
