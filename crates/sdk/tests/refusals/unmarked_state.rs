use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod vault {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity};

    // The state's name without its mark: a second `Vault` would be
    // synthesized beside this one, and every body lowered against it.
    struct Vault {
        held: Cell<Quantity>,
    }

    impl Vault {
        pub fn deposit(&mut self, funds: Bucket) {
            self.vault(funds.resource()).put(funds);
        }
    }
}

fn main() {}
