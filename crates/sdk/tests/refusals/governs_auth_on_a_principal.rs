use hyperscale_vm_sdk::blueprint;

#[blueprint(principals)]
mod contract {
    #[state]
    struct Contract {}

    impl Contract {
        // The `auth` cell names keys, and the account's own shard judges
        // it against the keys attesting an intent. A gate over it would
        // judge the same bytes against presented claims, which are
        // accounts, and refuse the intent the shard admitted.
        #[requires(governs(auth))]
        pub fn spend(&self) {}
    }
}

fn main() {}
