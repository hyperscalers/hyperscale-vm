use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Quantity, Vault};

    #[resource(grants(burn = self))]
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
        pub fn destroy(&mut self, amount: Quantity) {
            let taken = self.assets.take(amount);
            Unit::burn(taken);
        }
    }
}

fn main() {}
