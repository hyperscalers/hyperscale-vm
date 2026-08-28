use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    // Whichever attribute the lowering read, the other named a different
    // kind and different grants — a different resource.
    #[resource]
    #[resource(non_fungible, grants(mint = self))]
    struct Seat;

    #[state]
    struct Contract {
        held: Cell<u64>,
    }

    impl Contract {
        pub fn noop(&mut self) {
            self.held.set(0);
        }
    }
}

fn main() {}
