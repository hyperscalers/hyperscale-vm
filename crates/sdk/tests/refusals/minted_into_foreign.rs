use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Locked, Quantity, Vault, mint};

    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
        #[slot(3)]
        config: Locked<Settings>,
        #[slot(1)]
        #[denomination(config.asset)]
        assets: Cell<Vault>,
    }

    impl Contract {
        pub fn inflate(&mut self, amount: Quantity) {
            self.assets.vault().put(mint(b"", amount));
        }
    }
}

fn main() {}
