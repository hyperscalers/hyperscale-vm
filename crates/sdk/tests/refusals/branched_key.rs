use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        #[slot(16)] pointer: Cell<Address>,
    }

    impl Contract {
        // The condition is a state read, so nothing can judge which arm
        // routing takes before the body runs.
        pub fn on_state(&mut self, a: Address, b: Address) {
            let side = if self.pointer.get() == a { a } else { b };
            self.vault(side).declared();
        }
    }
}

fn main() {}
