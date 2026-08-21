use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {}

    impl Contract {
        // The Rust name is free; the published one is the seal's, and
        // the published one is what a caller names.
        #[name("instantiate")]
        pub fn set_up(&mut self) {}
    }
}

fn main() {}
