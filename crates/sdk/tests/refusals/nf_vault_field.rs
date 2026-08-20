use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{NfVault, Ordered};

    #[state]
    struct Contract {
        instances: Ordered<NfVault>,
    }

    impl Contract {
        pub fn count(&mut self) {
            let entries = self.instances.range(0, u128::MAX, 8);
            let _ = entries.count();
        }
    }
}

fn main() {}
