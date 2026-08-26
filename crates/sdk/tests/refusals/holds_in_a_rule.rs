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
        // A rule matches presented claims; possession is `#[proves]`.
        // Admitting a `holds` here — under a disjunction, or conjoined
        // beside the rule — would make authority a predicate engine,
        // which is the fence the grammar keeps.
        #[requires(holds(badge) || config.owner)]
        pub fn operate(&mut self, badge: Address, fee: Quantity) {
            let _ = badge;
            self.fee.set(fee);
        }
    }
}

fn main() {}
