use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[resource]
    struct Token;

    // The reservation covers a name wherever it is declared: a nested
    // module and a trait's default method would otherwise supply the
    // reading build's stub for a kernel-issuance spelling.
    mod inner {
        impl super::Token {
            fn __found() {}
        }
    }

    trait Records {
        fn __record() {}
    }

    #[state]
    struct Contract {
        held: Cell<u64>,
    }

    impl Contract {
        pub fn noop(&mut self) {
            self.held.set(0);
        }
    }
}

fn main() {}
