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
        // `cfg` names no configured resource — only `config.<field>` (or
        // the config field itself) reaches the record.
        #[slot(17)]
        #[holds(cfg.token)]
        sold: Vault,
    }

    impl Contract {
        pub fn count(&self) -> u64 {
            1
        }
    }
}

fn main() {}
