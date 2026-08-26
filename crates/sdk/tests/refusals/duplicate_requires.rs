use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {
    }

    impl Contract {
        // The same attribute twice is the same mistake as two different
        // ones: whichever the lowering read, the other said something.
        #[requires(self)]
        #[requires(self)]
        pub fn twice(&mut self) {}
    }
}

fn main() {}
