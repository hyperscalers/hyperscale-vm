use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity};

    struct Coupon;

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn forge(&mut self, amount: Quantity) -> Bucket {
            Coupon::mint(amount)
        }
    }
}

fn main() {}
