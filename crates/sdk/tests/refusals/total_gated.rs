use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Amount, Bucket, Keyed};

    #[state]
    struct Contract {
        #[role(1)]
        vaults: Keyed<Amount>,
    }

    impl Contract {
        // A gate turns callers away before the body runs, which is the one
        // refusal a total method promises cannot happen.
        #[total]
        #[guarded(self)]
        pub fn deposit(&mut self, funds: Bucket) {
            self.vaults.at(funds.resource()).put(funds);
        }
    }
}

fn main() {}
