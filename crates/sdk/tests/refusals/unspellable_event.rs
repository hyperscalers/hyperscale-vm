use hyperscale_vm_sdk::blueprint;

// An event resolves by its index and renders by its name, which is the
// identifier that declared it. The error table and the resource marks
// are held at the same place, being one band each.
#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[event]
    struct Réglé {
        amount: Quantity,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        pub fn settle(&mut self, fee: Quantity) {
            self.fee.set(fee);
            Réglé { amount: fee }.emit();
        }
    }
}

fn main() {}
