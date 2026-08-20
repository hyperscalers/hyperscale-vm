use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity, Vault};

    #[resource]
    struct Unit;

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
        pub fn pad(&mut self, amount: Quantity) {
            let mut taken = self.assets.vault().take(amount);
            taken.put(Unit::mint(amount));
            self.assets.vault().put(taken);
        }
    }
}

fn main() {}
