//! A leaf holds one value. A collection in one is a collection with
//! every property of one lost — many leaves, per entry routing,
//! independent writers — so the vocabulary's own slot kinds are what
//! replace it, and the macro says so on the field.
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::hbor::Capped;
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        seen: Cell<Capped<Vec<u64>, 4>>,
    }

    impl Contract {
        pub fn note(&mut self) {
            self.seen.set(Capped::empty());
        }
    }
}

fn main() {}
