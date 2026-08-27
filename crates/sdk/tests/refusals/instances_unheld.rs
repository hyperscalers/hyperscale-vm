use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Instances, NfBucket};

    #[state]
    struct Contract {
        stock: Instances,
    }

    impl Contract {
        pub fn file(&mut self, instances: NfBucket) {
            self.stock.whole().file(instances);
        }
    }
}

fn main() {}
