use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    #[resource(initial(1_000))]
    struct Seat;

    #[state]
    struct Contract {}

    impl Contract {
        // What the component comes up holding is `initial(..)`'s to say,
        // so the bring-up's body cannot claim to hand anything back.
        pub fn instantiate(&mut self) -> Bucket {
            Seat::mint(Quantity::from_subunits(1))
        }
    }
}

fn main() {}
