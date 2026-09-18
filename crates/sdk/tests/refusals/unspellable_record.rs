use hyperscale_vm_sdk::blueprint;

// A declared type publishes under its own identifier, which is what a
// consumer resolves its shape by when reading a leaf.
#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[record]
    struct Reçu {
        amount: Quantity,
    }

    #[state]
    struct Contract {
        last: Cell<Reçu>,
    }

    impl Contract {
        pub fn settle(&mut self, fee: Quantity) {
            self.last.set(Reçu { amount: fee });
        }
    }
}

fn main() {}
