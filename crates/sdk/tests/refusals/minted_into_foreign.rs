use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity, Vault, mint};

    #[config]
    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
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
