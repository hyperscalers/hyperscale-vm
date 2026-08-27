use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Quantity, Vault};

    #[config]
    struct Settings {
        x: Address,
        y: Address,
    }

    #[state]
    struct Contract {
        #[holds(config.x)]
        sold: Vault,
        #[holds(config.y)]
        bought: Vault,
    }

    impl Contract {
        pub fn rebalance(&mut self, amount: Quantity) {
            let taken = self.sold.take(amount);
            self.bought.put(taken);
        }
    }
}

fn main() {}
