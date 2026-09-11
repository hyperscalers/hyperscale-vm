use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity};

    #[resource]
    struct Token;

    #[state]
    struct Contract {
        held: Cell<u64>,
    }

    impl Contract {
        // A supply is founded where the component becomes actual and
        // nowhere else: a method founding one again would be minting
        // under the one word no `Mint` entry governs.
        pub fn refound(&mut self) -> Bucket {
            Token::__record(0);
            Token::__found(Quantity::from_subunits(5))
        }
    }
}

fn main() {}
