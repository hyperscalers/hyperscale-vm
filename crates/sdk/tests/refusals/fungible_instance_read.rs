use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[resource]
    struct Coupon;

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        pub fn note(&mut self, id: u64) {
            if let Some(coupon) = Coupon::filed(id) {
                let _ = coupon;
                self.noted.set(id);
            }
        }
    }
}

fn main() {}
