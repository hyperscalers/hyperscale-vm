use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        #[role(1)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn either(&mut self, flag: u64, a: Address, b: Address) -> Bucket {
            if flag == 0 {
                return self.vaults.at(a).take(1);
            }
            self.vaults.at(b).take(1)
        }
    }
}

fn main() {}
