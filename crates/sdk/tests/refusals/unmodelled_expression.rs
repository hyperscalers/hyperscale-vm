use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        // The walk is exhaustive, so a form it does not model is refused
        // by name rather than skipped — a skip would be a declaration
        // missing whatever the form did inside it.
        pub fn note(&mut self, seed: u64) {
            let folded = unsafe { seed.unchecked_mul(2) };
            self.noted.set(folded);
        }
    }
}

fn main() {}
