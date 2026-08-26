use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;

    #[state]
    struct Contract {
    }

    // `config.<field>` resolves against one namespace; two structs
    // would leave a gate naming the first refused over a field the
    // author can see declared.
    #[config]
    struct Terms {
        admin: Address,
    }

    #[config]
    struct MoreTerms {
        backup: Address,
    }

    impl Contract {
        #[requires(config.admin)]
        pub fn operate(&mut self) {}
    }
}

fn main() {}
