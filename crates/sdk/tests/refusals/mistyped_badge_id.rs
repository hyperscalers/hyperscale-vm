use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;

    #[state]
    struct Contract {
    }

    impl Contract {
        // The instance id is read as a `u64`; an address in that slot is
        // a different claim than the author wrote.
        #[proves(badge[id])]
        pub fn operate(&mut self, badge: Address, id: Address) {}
    }
}

fn main() {}
