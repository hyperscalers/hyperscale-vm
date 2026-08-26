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
        // A count past the claims it counts: a gate nobody can meet is
        // not a gate anybody meant, and the vocabulary holds no rule for
        // it. Refused on the line rather than at the tracer, where the
        // shape is all that is left.
        #[requires(n_of(3, config.chair, config.deputy))]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
