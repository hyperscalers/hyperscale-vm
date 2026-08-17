use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Vault};

    #[state]
    struct Contract {
        #[role(1)]
        pot: Cell<Vault>,
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            self.pot.vault().put(funds);
        }
    }
}

fn main() {}
