use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        owner: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // Conjoined beside the rule rather than within it, and refused
        // on the same terms: `#[requires]` names claims, and possession
        // is spelled `#[proves]`.
        #[requires(owner && holds(badge))]
        pub fn operate(&mut self, badge: Address, fee: Quantity) {
            let _ = badge;
            self.fee.set(fee);
        }
    }
}

fn main() {}
