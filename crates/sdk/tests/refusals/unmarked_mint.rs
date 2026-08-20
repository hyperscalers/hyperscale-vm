use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity, mint};

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn forge(&mut self, amount: Quantity) -> Bucket {
            mint(b"", amount)
        }
    }
}

fn main() {}
