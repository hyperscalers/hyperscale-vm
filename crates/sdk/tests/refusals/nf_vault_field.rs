use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{NfVault, OrderKey, Ordered};

    #[state]
    struct Contract {
        instances: Ordered<NfVault>,
    }

    impl Contract {
        pub fn count(&mut self) {
            let entries =
                self.instances
                    .range(OrderKey::at(0, 0), OrderKey::at(u64::MAX, u64::MAX), 8);
            let _ = entries.count();
        }
    }
}

fn main() {}
