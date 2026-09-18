use hyperscale_vm_sdk::blueprint;

// A method's identifier is its wasm export name and its row in the
// package's method table, so it is held to what a name is made of on the
// identifier itself.
#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        pub fn régler(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
