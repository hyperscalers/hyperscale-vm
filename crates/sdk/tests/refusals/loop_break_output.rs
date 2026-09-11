use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        pub fn first(&mut self, a: ResourceAddr) -> Bucket {
            loop {
                break self.till.at(a).take(Quantity::from_subunits(1));
            }
        }
    }
}

fn main() {}
