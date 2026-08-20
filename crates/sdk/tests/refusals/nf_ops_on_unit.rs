//! A unit collection is a membership set: its entries hold no value, so
//! the instance operations are not there to reach. The refusal is the
//! type's own — `take` lives on the holdings element alone.
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod roster {
    use hyperscale_vm_sdk::state::{Ids, NfBucket, Ordered};

    #[state]
    struct Roster {
        seen: Ordered<()>,
    }

    impl Roster {
        pub fn grab(&mut self, ids: Ids) -> NfBucket {
            self.seen.of(7u64).all(8).take(ids)
        }
    }
}

fn main() {}
