use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn either(&mut self, flag: u64, a: Address, b: Address) -> Bucket {
            if flag == 0 {
                return self.vault(a).take(Quantity::from_subunits(1));
            }
            self.vault(b).take(Quantity::from_subunits(1))
        }
    }
}

fn main() {}
