use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity, mint};

    #[resource(non_fungible)]
    struct OwnerBadge;

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn forge(&mut self) -> Bucket {
            mint(b"owner-badge", 1)
        }
    }
}

fn main() {}
