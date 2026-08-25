use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Vault};

    #[state]
    struct Contract {
        // A package field on the protocol's own band. Refusing by number
        // rather than by shape is what makes the band hold: a package's
        // own keyed vault is the same shape as the protocol's, so a
        // misnumbered pool side would have nothing in it to disagree
        // with — and every one of these cells is found by derivation by
        // somebody who is not its owner.
        #[slot(1)]
        mine: Keyed<Vault>,
    }

    impl Contract {
        pub fn deposit(&mut self, funds: Bucket) {
            self.mine.at(funds.resource()).put(funds);
        }
    }
}

fn main() {}
