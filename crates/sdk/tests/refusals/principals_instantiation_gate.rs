use hyperscale_vm_sdk::blueprint;

#[blueprint(principals)]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Config};

    // A principals package instantiates nothing, so an instantiation gate
    // on its configuration binds nothing — refused rather than silently
    // stripped.
    #[config]
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
