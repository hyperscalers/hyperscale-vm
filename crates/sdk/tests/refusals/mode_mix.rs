use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn peek_then_take(&mut self, a: Address, amount: u128) {
            let mut vault = self.vault(a);
            let _ = vault.balance();
            vault.reserve(amount);
        }
    }
}

fn main() {}
