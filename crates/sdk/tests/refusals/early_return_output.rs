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
        pub fn either(&mut self, flag: u64, a: ResourceAddr, b: ResourceAddr) -> Bucket {
            if flag == 0 {
                return self.till.at(a).take(Quantity::from_subunits(1));
            }
            self.till.at(b).take(Quantity::from_subunits(1))
        }
    }
}

fn main() {}
