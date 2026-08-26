use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity, recall};

    #[resource(non_fungible, grants(mint = self, recall = self))]
    struct Registered;

    #[state]
    struct Contract {}

    impl Contract {
        // The free spelling names a mark, and the mark says the kind:
        // instances live as entries of an interval, not as a balance, so
        // the point vault this would reach is a cell nothing is ever in.
        pub fn seize(&mut self, holder: Address, slot: u64, amount: Quantity) -> Bucket {
            recall(holder, slot, Registered::address(), amount)
        }
    }
}

fn main() {}
