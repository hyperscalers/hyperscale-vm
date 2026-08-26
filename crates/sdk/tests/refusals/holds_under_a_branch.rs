use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        owner: Address,
        deputy: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // Conjoined, but inside a branch of a disjunction: the
        // conjunction the plan admits is the top-level one, and this is
        // not it.
        #[requires(config.owner || (holds(badge) && config.deputy))]
        pub fn operate(&mut self, badge: Address, fee: Quantity) {
            let _ = badge;
            self.fee.set(fee);
        }
    }
}

fn main() {}
