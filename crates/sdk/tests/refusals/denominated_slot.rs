use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Config, Vault};

    #[config]
    struct Sides {
        x: ResourceAddr,
        y: ResourceAddr,
    }

    #[state]
    struct Contract {
        #[slot(16)]
        settings: Config<Sides>,
        #[slot(17)]
        #[holds(config.x)]
        sold: Vault,
        #[slot(17)]
        #[holds(config.y)]
        bought: Vault,
    }

    impl Contract {
        pub fn sides(&self) -> u64 {
            2
        }
    }
}

fn main() {}
