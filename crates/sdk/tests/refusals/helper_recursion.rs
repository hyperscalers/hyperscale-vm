use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn poke(&mut self, deep: bool) {
            self.settle(deep);
        }

        // Splicing substitutes a helper's body where it is called, so a
        // cycle would substitute forever.
        fn settle(&mut self, deep: bool) {
            if deep {
                self.drain(false);
            }
        }

        fn drain(&mut self, deep: bool) {
            if deep {
                self.settle(false);
            }
        }
    }
}

fn main() {}
