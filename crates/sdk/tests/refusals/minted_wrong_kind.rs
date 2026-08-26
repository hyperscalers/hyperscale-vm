use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity};

    #[resource(non_fungible, grants(mint = self))]
    struct OwnerBadge;

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn forge(&mut self) -> Bucket {
            OwnerBadge::mint(1)
        }
    }
}

fn main() {}
