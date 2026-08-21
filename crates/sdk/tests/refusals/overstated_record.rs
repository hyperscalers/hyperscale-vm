use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[resource(non_fungible, display_digits = 6)]
    struct OwnerBadge;

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn note(&mut self, value: Quantity) {
            self.supply.set(value);
        }
    }
}

fn main() {}
