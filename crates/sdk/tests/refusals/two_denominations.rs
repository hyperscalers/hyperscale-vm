use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Locked, Quantity, Vault};

    struct Settings {
        base: Address,
        quote: Address,
    }

    #[state]
    struct Contract {
        #[role(3)]
        config: Locked<Settings>,
        #[role(1)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            let settings = self.config.locked();
            let (half, rest) = funds.split(Quantity::ZERO.ratio_to(Quantity::ZERO).unwrap());
            self.vaults.at(settings.base).put(half);
            self.vaults.at(settings.quote).put(rest);
        }
    }
}

fn main() {}
