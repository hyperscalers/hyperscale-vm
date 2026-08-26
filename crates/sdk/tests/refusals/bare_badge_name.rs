use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[resource(grants(mint = self))]
    struct OwnerBadge;

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // A badge the package issues has one spelling too, and it is the
        // same one every other position uses.
        #[requires(OwnerBadge)]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
