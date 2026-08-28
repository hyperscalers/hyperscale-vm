use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        // The lowering emits `__value_N` into this body, so a `__`-named
        // local would shadow one the effects read.
        pub fn touch(&mut self) -> Quantity {
            let __value_0 = Quantity::ZERO;
            __value_0
        }
    }
}

fn main() {}
