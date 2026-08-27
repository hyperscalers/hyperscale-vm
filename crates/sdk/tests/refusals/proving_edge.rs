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
        // A proving call is evidence, never value flow: the refund
        // belongs to a method the proof gates.
        #[proves(self)]
        pub fn pass(&mut self, asset: ResourceAddr, amount: Quantity) -> Bucket {
            self.till.at(asset).take(amount)
        }
    }
}

fn main() {}
