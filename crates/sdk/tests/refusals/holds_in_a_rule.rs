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
        // Possession conjoins as its own condition beside the rule;
        // inside one — under a disjunction — authority would become a
        // predicate engine, which is the fence the grammar keeps.
        #[requires(holds(badge) || owner)]
        pub fn operate(&mut self, badge: Address, fee: Quantity) {
            let _ = badge;
            self.fee.set(fee);
        }
    }
}

fn main() {}
