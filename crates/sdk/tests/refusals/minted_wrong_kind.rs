//! A mint produces the kind its mark declares, so a non-fungible mint
//! is an `NfBucket` however it is spelled. The refusal is the type's
//! own — the produced edge does not fit the fungible return the author
//! wrote, and the compiler answers before the macro has an opinion.
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity};

    #[resource(non_fungible, grants(mint = self))]
    struct OwnerBadge;

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn forge(&mut self) -> Bucket {
            OwnerBadge::mint(1)
        }
    }
}

fn main() {}
