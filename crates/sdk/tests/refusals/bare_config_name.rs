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
        // A configuration field has one spelling, and a bare name is not
        // it: the refusal says which field this is and how to write it.
        #[requires(chair)]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
