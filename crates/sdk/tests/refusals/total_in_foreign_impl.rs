use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    struct Helper;

    impl Helper {
        // Only the state struct's methods publish; a mark on anything
        // else describes nothing.
        #[total]
        pub fn noted(&self) -> u64 {
            0
        }
    }

    impl Contract {
        pub fn touch(&mut self) {}
    }
}

fn main() {}
