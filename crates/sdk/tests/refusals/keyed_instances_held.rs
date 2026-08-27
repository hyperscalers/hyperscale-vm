use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Instances, Keyed, NfBucket};

    #[config]
    struct Settings {
        mark: ResourceAddr,
    }

    #[state]
    struct Contract {
        #[holds(config.mark)]
        stock: Keyed<Instances>,
    }

    impl Contract {
        pub fn file(&mut self, instances: NfBucket) {
            self.stock.of(instances.resource()).whole().file(instances);
        }
    }
}

fn main() {}
