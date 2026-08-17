use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Locked, Quantity, Vault, burn};

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
        pub fn destroy(&mut self, amount: Quantity) {
            let taken = self.assets.vault().take(amount);
            burn(b"", taken);
        }
    }
}

fn main() {}
