use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Vault};

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        // A caller waits at the gate whatever the body promises, so the
        // mark beside one is inert rather than false.
        #[total]
        #[requires(self)]
        pub fn deposit(&mut self, funds: Bucket) {
            self.till.at(funds.resource()).put(funds);
        }
    }
}

fn main() {}
