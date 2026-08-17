use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Keyed, Quantity};

    #[state]
    struct Contract {
        #[role(1)]
        vaults: Keyed<Quantity>,
    }

    impl Contract {
        pub fn hidden(&mut self, a: Address) {
            let credit = || self.vaults.at(a).declared();
            credit();
        }
    }
}

fn main() {}
