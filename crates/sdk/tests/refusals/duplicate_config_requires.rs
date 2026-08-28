use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Config};

    // Two gates on the configuration are the same mistake as two on a
    // method: whichever the lowering read, the other said something.
    #[config]
    #[requires(config.founder)]
    #[requires(config.founder)]
    struct Settings {
        founder: Address,
    }

    #[state]
    struct Contract {
        settings: Config<Settings>,
        held: Cell<Address>,
    }

    impl Contract {
        pub fn touch(&self) {}
    }
}

fn main() {}
