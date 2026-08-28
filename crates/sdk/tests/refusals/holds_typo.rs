use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Config, Vault};

    #[config]
    struct Sides {
        token: ResourceAddr,
    }

    #[state]
    struct Contract {
        #[slot(16)]
        settings: Config<Sides>,
        // `tokn` is not a field of the configuration, so no method touches
        // the vault to catch it — the holding would drop silently.
        #[slot(17)]
        #[holds(config.tokn)]
        sold: Vault,
    }

    impl Contract {
        pub fn count(&self) -> u64 {
            1
        }
    }
}

fn main() {}
