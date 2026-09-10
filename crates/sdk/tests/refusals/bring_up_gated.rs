use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Cell;

    #[config]
    #[requires(config.founder)]
    struct Settings {
        founder: Address,
    }

    #[state]
    struct Contract {
        seeded: Cell<u64>,
    }

    impl Contract {
        // The gate is the configuration's; a second one here would be a
        // second answer to who may bring the component up.
        #[requires(config.founder)]
        pub fn instantiate(&mut self, seed: u64) {
            self.seeded.set(seed);
        }
    }
}

fn main() {}
