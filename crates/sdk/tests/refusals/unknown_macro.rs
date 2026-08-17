use hyperscale_vm_sdk::blueprint;

macro_rules! credit {
    ($contract:expr, $addr:expr) => {
        $contract.vaults.at($addr).add(0)
    };
}

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        #[role(1)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn wrapped(&mut self, a: Address) {
            credit!(self, a);
        }
    }
}

fn main() {}
