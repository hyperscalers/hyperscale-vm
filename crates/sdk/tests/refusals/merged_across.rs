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
        pub fn pad(&mut self, amount: Quantity) {
            let mut taken = self.assets.take(amount);
            taken.put(Unit::mint(amount));
            self.assets.put(taken);
        }
    }
}

fn main() {}
