use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Keyed};

    #[state]
    struct Contract {
        #[role(16)]
        seen: Keyed<u64>,
        #[role(16)]
        stamped: Cell<u64>,
    }

    impl Contract {
        pub fn stamp(&mut self, at: u64) {
            self.stamped.set(at);
        }
    }
}

fn main() {}
