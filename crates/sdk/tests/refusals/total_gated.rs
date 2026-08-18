use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Bucket;

    #[state]
    struct Contract {
    }

    impl Contract {
        // A gate turns callers away before the body runs, which is the one
        // refusal a total method promises cannot happen.
        #[total]
        #[guarded(self)]
        pub fn deposit(&mut self, funds: Bucket) {
            self.vault(funds.resource()).put(funds);
        }
    }
}

fn main() {}
