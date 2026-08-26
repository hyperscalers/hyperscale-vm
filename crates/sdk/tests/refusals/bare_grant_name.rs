use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    // The grant position reads the same grammar the gate does, so a bare
    // name is refused here in the same words.
    #[resource(non_fungible, grants(mint = self, recall = warden))]
    struct Seat;

    #[config]
    struct Settings {
        warden: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
