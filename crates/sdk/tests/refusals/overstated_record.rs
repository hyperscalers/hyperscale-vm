use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[resource(non_fungible)]
    struct OwnerBadge;

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn found(&mut self) {
            OwnerBadge::create(6);
        }
    }
}

fn main() {}
