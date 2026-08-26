use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    #[resource]
    struct Ungranted;

    #[state]
    struct Contract {}

    impl Contract {
        pub fn issue(&mut self, amount: Quantity) -> Bucket {
            Ungranted::mint(amount)
        }
    }
}

fn main() {}
