use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[error]
    enum Error {
        Empty,
    }

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        // A refusal needs an arm to leave through, which the return type
        // does not name.
        pub fn drain(&mut self) -> Quantity {
            Err(Error::Empty)
        }
    }
}

fn main() {}
