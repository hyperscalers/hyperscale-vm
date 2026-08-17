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
        pub fn peek_then_take(&mut self, a: Address, amount: u128) {
            let mut vault = self.vaults.at(a);
            let _ = vault.balance();
            vault.reserve(amount);
        }
    }
}

fn main() {}
