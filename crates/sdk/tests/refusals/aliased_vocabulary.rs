use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};
    // The macro matches types by their last path segment, so aliasing
    // `NfBucket` to `Bucket` would lower `echo`'s parameter as the
    // fungible `Bucket` the alias only spells.
    use hyperscale_vm_sdk::state::NfBucket as Bucket;

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn echo(&mut self, funds: Bucket) -> Bucket {
            funds
        }
    }
}

fn main() {}
