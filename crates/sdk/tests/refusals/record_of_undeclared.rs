use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;

    #[state]
    struct Contract {}

    impl Contract {
        pub fn seize(&mut self) {
            Address::create();
        }
    }
}

fn main() {}
