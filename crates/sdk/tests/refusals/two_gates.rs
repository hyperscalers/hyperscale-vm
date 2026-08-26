use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {
    }

    impl Contract {
        // An author writing both means both; a lowering that reads one
        // and strips the other enforces less than the text says.
        #[requires(self)]
        #[proves(self)]
        pub fn both(&mut self) {}
    }
}

fn main() {}
