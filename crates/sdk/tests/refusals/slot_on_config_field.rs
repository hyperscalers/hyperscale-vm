use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;

    #[config]
    struct Terms {
        // A config slot is fixed by declaration order; a pin is a
        // `#[state]` field's to state.
        #[slot(17)]
        asset: ResourceAddr,
    }

    impl Contract {
        pub fn noted(&self) -> u64 {
            17
        }
    }
}

fn main() {}
