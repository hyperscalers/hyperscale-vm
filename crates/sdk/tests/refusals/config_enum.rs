use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {
    }

    // The configuration scan reads structs, so an enum here would
    // declare nothing at all.
    #[config]
    enum Terms {
        Fast,
        Slow,
    }

    impl Contract {
        pub fn check(&self) {}
    }
}

fn main() {}
