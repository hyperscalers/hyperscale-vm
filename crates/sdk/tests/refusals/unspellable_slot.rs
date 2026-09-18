use hyperscale_vm_sdk::blueprint;

// A slot's name is what a consumer reads a stored leaf back as, so a
// state field is held to a name like every other declaration.
#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        frais_élevés: Cell<Quantity>,
    }

    impl Contract {
        pub fn settle(&mut self, fee: Quantity) {
            self.frais_élevés.set(fee);
        }
    }
}

fn main() {}
