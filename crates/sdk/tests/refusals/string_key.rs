use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Keyed;

    #[state]
    struct Contract {
        tallies: Keyed<u64>,
    }

    impl Contract {
        pub fn note(&mut self) {
            // Nothing hashes a string, so the wrong type errs while it
            // is typed rather than after expansion.
            self.tallies.at("alice").set(1);
        }
    }
}

fn main() {}
