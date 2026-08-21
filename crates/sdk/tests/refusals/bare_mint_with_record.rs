use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::NfBucket;

    #[resource(non_fungible)]
    struct OwnerBadge;

    #[state]
    struct Contract {}

    impl Contract {
        pub fn found(&mut self) -> NfBucket {
            OwnerBadge::mint(0, OwnerBadge)
        }
    }
}

fn main() {}
