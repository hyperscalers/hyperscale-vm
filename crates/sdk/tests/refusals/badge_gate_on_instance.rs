use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;

    #[state]
    struct Contract {}

    impl Contract {
        // A badge held by a component is an asset, not a credential, so
        // presentation belongs to the principals blueprint alone.
        #[proves(badge)]
        pub fn operate(&self, badge: Address) {}
    }
}

fn main() {}
