use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Keyed};

    #[state]
    struct Contract {
        #[role(1)]
        vaults: Keyed<Amount>,
    }

    impl Contract {
        pub fn peek_then_take(&mut self, a: Address, amount: u128) {
            let mut vault = self.vaults.at(a);
            let _ = vault.get();
            vault.reserve(amount);
        }
    }
}

fn main() {}
