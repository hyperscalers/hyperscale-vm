use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Vault};

    #[state]
    struct Contract {
        // A package field on the protocol's own band, and the hardest
        // case: the claims cell and a vault are both a keyed vault, so
        // nothing in the shape tells them apart. Refusing the band by
        // number rather than by shape is what makes the cell reachable
        // only through `claims()`.
        #[slot(2)]
        mine: Keyed<Vault>,
    }

    impl Contract {
        pub fn deposit(&mut self, funds: Bucket) {
            self.mine.at(funds.resource()).put(funds);
        }
    }
}

fn main() {}
