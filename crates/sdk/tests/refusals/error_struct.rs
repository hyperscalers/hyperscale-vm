use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {
    }

    // The error table is an enum's variants, so a struct here would
    // declare nothing at all.
    #[error]
    struct Refusal {
        code: u32,
    }

    impl Contract {
        pub fn check(&self) {}
    }
}

fn main() {}
