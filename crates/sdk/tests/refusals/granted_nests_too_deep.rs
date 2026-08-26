use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    // The depth cap is the vocabulary's and binds a granted rule exactly
    // as it binds a gate — one parser, and the refusal names which
    // position wrote it.
    #[resource(grants(
        mint = n_of(1, n_of(1, n_of(1, n_of(1, config.chair))))
    ))]
    struct Seat;

    #[config]
    struct Settings {
        chair: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
