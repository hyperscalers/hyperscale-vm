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
        // A threshold branch is inside a rule, so it is refused there
        // too — depth does not buy possession a way in.
        #[requires(n_of(2, owner, holds(badge)))]
        pub fn operate(&mut self, badge: Address, fee: Quantity) {
            let _ = badge;
            self.fee.set(fee);
        }
    }
}

fn main() {}
