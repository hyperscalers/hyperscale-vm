use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Keyed, Quantity, Vault};

    #[config]
    struct Settings {
        left: Address,
    }

    #[state]
    struct Contract {
        vaults: Keyed<Vault>,
    }

    impl Contract {
        // A selection whose arms are an address and a scalar: whatever it
        // chooses would cross the call boundary as one value, and no one
        // export parameter carries both shapes.
        pub fn confused(&mut self, pick: Address, amount: Quantity) {
            let settings = self.config().locked();
            let key = if pick == settings.left {
                settings.left
            } else {
                7
            };
            let _ = self.vaults.at(key).take(amount);
        }
    }
}

fn main() {}
