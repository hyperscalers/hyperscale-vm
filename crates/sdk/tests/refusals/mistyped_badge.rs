use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Quantity;

    #[state]
    struct Contract {
    }

    impl Contract {
        // The runtime reads a badge as an address; a parameter declared
        // anything else would compile and trap at the first call.
        #[proves(badge)]
        pub fn operate(&mut self, badge: Quantity) {}
    }
}

fn main() {}
