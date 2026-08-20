use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    #[resource]
    struct Coupon {
        issued_at: u64,
    }

    #[state]
    struct Contract {}

    impl Contract {
        pub fn forge(&mut self, amount: Quantity) -> Bucket {
            Coupon::mint(amount)
        }
    }
}

fn main() {}
