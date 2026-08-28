use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[resource]
    struct Token;

    // The kernel-issuance spelling, supplied by hand: the fence is the
    // name itself, not the stub the reading build would otherwise miss.
    impl Token {
        fn __found() {}
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
