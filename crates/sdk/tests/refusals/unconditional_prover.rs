use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Vault};

    #[config]
    struct Settings {
        asset: ResourceAddr,
    }

    #[state]
    struct Contract {
        #[holds(config.asset)]
        till: Vault,
    }

    impl Contract {
        // Banking the payment is not judging it: without an error arm
        // this body cannot decline, so the claim it mints would belong
        // to whoever calls first.
        #[proves(self)]
        pub fn pass(&mut self, payment: Bucket) {
            self.till.put(payment);
        }
    }
}

fn main() {}
