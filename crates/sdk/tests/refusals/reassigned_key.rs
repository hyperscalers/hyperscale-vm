use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        #[slot(1)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn rebound(&mut self, flag: u64, a: Address, b: Address) {
            let mut key = a;
            if flag == 0 {
                key = b;
            }
            self.vaults.at(key).declared();
        }
    }
}

fn main() {}
