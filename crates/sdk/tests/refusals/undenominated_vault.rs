use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Vault};

    #[state]
    struct Contract {
        pot: Vault,
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            self.pot.put(funds);
        }
    }
}

fn main() {}
