use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        #[role(1)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn credit(&mut self, a: Address) {
            self.vaults.at(a).add(0);
        }

        pub fn double(&mut self, a: Address) {
            self.credit(a);
            self.credit(a);
        }
    }
}

fn main() {}
