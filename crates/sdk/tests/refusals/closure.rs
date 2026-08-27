use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Keyed, Vault};

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        pub fn hidden(&mut self, a: ResourceAddr) {
            let credit = || self.till.at(a).declared();
            credit();
        }
    }
}

fn main() {}
