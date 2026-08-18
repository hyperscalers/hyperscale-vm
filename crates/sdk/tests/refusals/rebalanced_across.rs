use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity, Vault};

    #[config]
    struct Settings {
        x: Address,
        y: Address,
    }

    #[state]
    struct Contract {
        #[denomination(config.x)]
        sold: Cell<Vault>,
        #[denomination(config.y)]
        bought: Cell<Vault>,
    }

    impl Contract {
        pub fn rebalance(&mut self, amount: Quantity) {
            let taken = self.sold.vault().take(amount);
            self.bought.vault().put(taken);
        }
    }
}

fn main() {}
