use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    #[resource(grants(mint = self))]
    struct Ungranted;

    #[state]
    struct Contract {}

    impl Contract {
        pub fn seize(&mut self, holder: Address, slot: u64, amount: Quantity) -> Bucket {
            Ungranted::recall(holder, slot, amount)
        }
    }
}

fn main() {}
