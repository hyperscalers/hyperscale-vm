use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Vault};

    #[config]
    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
        #[holds(config.asset)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            self.vaults.at(funds.resource()).put(funds);
        }
    }
}

fn main() {}
