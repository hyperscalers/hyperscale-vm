use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Quantity;

    #[state]
    struct Contract {
        count: hyperscale_vm_sdk::state::Cell<u64>,
    }

    impl Contract {
        pub fn set(&mut self, __value_0: Quantity) {
            let _ = __value_0;
        }
    }
}

fn main() {}
