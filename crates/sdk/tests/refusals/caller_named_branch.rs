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
        // One branch of a threshold the caller names is one branch the
        // caller satisfies for free, so the whole gate admits everyone.
        // Every leaf answers, whichever position it sits in.
        #[requires(chair || whoever)]
        pub fn set_fee(&mut self, whoever: Address, fee: Quantity) {
            let _ = whoever;
            self.fee.set(fee);
        }
    }
}

fn main() {}
