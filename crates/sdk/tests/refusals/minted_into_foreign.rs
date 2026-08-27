use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Quantity, Vault};

    #[resource(grants(mint = self))]
    struct Unit;

    #[config]
    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
        #[holds(config.asset)]
        assets: Vault,
    }

    impl Contract {
        pub fn inflate(&mut self, amount: Quantity) {
            self.assets.put(Unit::mint(amount));
        }
    }
}

fn main() {}
