use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        #[role(2)]
        stamped: Cell<u64>,
    }

    impl Contract {
        pub fn stamp(&mut self, at: u64) {
            self.stamped.set(at);
        }
    }
}

fn main() {}
