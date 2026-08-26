use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        chair: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // The same refusal from inside an explicit threshold, and from
        // a position that is neither first nor last: the walk reaches
        // every leaf rather than the root alone.
        #[requires(n_of(2, config.chair, whoever, config.chair))]
        pub fn set_fee(&mut self, whoever: Address, fee: Quantity) {
            let _ = whoever;
            self.fee.set(fee);
        }
    }
}

fn main() {}
