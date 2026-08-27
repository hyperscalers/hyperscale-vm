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
        pub fn credit(&mut self, a: ResourceAddr) {
            self.till.at(a).declared_credit();
        }

        pub fn double(&mut self, a: ResourceAddr) {
            self.credit(a);
            self.credit(a);
        }
    }
}

fn main() {}
