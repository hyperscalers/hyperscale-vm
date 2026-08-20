use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[resource]
    struct Coupon;

    #[state]
    struct Contract {
        supply: Cell<Quantity>,
    }

    impl Contract {
        pub fn open(&mut self) {
            Coupon::create();
        }
    }
}

fn main() {}
