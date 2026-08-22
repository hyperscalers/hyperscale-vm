use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Cell;

    #[config]
    struct Settings {
        parties: Vec<Address>,
    }

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        pub fn count(&mut self) {
            self.noted.set(how_many(&self.config().parties));
        }
    }

    fn how_many(parties: &[Address]) -> u64 {
        parties.len() as u64
    }
}

fn main() {}
