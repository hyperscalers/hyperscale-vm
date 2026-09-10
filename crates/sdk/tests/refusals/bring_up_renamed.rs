use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {}

    impl Contract {
        // The method's own name is what marks it as the seal's body, and
        // the seal publishes as `instantiate`.
        #[name("set-up")]
        pub fn instantiate(&mut self) {}
    }
}

fn main() {}
