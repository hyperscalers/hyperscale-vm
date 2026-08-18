use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        pointer: Cell<Address>,
    }

    impl Contract {
        // The condition is derivable and one arm is not, so the
        // selection as a whole is a key nothing can name before the body
        // runs.
        pub fn from_state(&mut self, flag: u64, a: Address) {
            let side = if flag == 0 { a } else { self.pointer.get() };
            self.vault(side).declared();
        }
    }
}

fn main() {}
