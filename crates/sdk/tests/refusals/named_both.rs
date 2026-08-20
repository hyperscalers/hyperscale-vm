use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[resource]
    struct owner;

    #[config]
    struct Settings {
        owner: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // A badge this instance issues and an address fixed at creation
        // are different authorities; one name for both says neither.
        #[requires(owner)]
        pub fn operate(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
