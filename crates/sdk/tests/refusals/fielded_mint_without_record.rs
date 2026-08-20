use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::NfBucket;

    #[resource(non_fungible)]
    struct Seat {
        operator: u64,
    }

    #[state]
    struct Contract {}

    impl Contract {
        pub fn seat(&mut self) -> NfBucket {
            self.resource::<Seat>().create();
            Seat::mint(0)
        }
    }
}

fn main() {}
