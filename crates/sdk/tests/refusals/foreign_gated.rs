use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {
    }

    struct Helper;

    impl Helper {
        // `pub`, gated, and still publishing nothing: only the state
        // struct's own methods lower.
        #[requires(self)]
        pub fn shutdown(&mut self) {}
    }

    impl Contract {
        pub fn check(&self) {}
    }
}

fn main() {}
