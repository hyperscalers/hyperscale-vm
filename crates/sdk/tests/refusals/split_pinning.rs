use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    // Pin-all-or-none is judged per struct, so putting the unpinned
    // fields in one and the pinned in another would slip the mix past
    // it — the refusal of the second struct is what closes that door.
    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    #[state]
    struct Pinned {
        #[slot(17)]
        hoard: Cell<Quantity>,
    }

    impl Contract {
        pub fn read(&self) -> Quantity {
            self.held.get()
        }
    }
}

fn main() {}
