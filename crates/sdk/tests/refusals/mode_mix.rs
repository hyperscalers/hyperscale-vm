use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        pub fn peek_then_take(&mut self, a: ResourceAddr, amount: Quantity) {
            let mut vault = self.till.at(a);
            let _ = vault.balance();
            vault.reserve(amount);
        }
    }
}

fn main() {}
