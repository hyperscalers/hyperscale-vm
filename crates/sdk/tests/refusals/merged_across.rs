use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Locked, Quantity, Vault, issue};

    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
        #[role(3)]
        config: Locked<Settings>,
        #[role(1)]
        #[denomination(config.asset)]
        assets: Cell<Vault>,
    }

    impl Contract {
        pub fn pad(&mut self, amount: Quantity) {
            let mut taken = self.assets.vault().take(amount);
            taken.put(issue(b"", amount));
            self.assets.vault().put(taken);
        }
    }
}

fn main() {}
