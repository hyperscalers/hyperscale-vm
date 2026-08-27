use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Vault};

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        // A gate turns callers away before the body runs, which is the one
        // refusal a total method promises cannot happen.
        #[total]
        #[requires(self)]
        pub fn deposit(&mut self, funds: Bucket) {
            self.till.at(funds.resource()).put(funds);
        }
    }
}

fn main() {}
