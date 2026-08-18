use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Locked, Vault};

    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
        #[slot(3)]
        config: Locked<Settings>,
        #[slot(1)]
        #[denomination(config.asset)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn bank(&mut self, holder: Address, funds: Bucket) {
            self.vaults.at(holder).put(funds);
        }
    }
}

fn main() {}
