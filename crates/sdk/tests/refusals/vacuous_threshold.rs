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
        // And a count of nothing, which admits everyone: the same
        // refusal from the other end of the range.
        #[requires(n_of(0, chair, deputy))]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
