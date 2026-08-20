use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, NfBucket, Quantity};

    #[resource(non_fungible)]
    struct OwnerBadge;

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn retire(&mut self, badge: NfBucket) {
            OwnerBadge::burn(badge);
        }
    }
}

fn main() {}
