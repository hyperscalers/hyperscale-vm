use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        #[slot(1)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn conjure(&mut self, holder: Address) {
            self.vaults.at(holder).set(Quantity::from_subunits(1_000));
        }
    }
}

fn main() {}
