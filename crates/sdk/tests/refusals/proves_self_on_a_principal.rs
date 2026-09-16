use hyperscale_vm_sdk::blueprint;

#[blueprint(principals)]
mod contract {
    #[state]
    struct Contract {}

    impl Contract {
        // An account's virtual badge is attested by its own shard, and
        // the claim rides the signature of every intent acting as it.
        // Nothing is left for a body to vouch for.
        #[proves(self)]
        pub fn authorize(&self) {}
    }
}

fn main() {}
