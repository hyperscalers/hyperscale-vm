use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[resource]
    struct Token;

    #[state]
    struct Contract {
        held: Cell<u64>,
    }

    impl Contract {
        // Founding is the synthesized bring-up's: the authored half of
        // the bring-up is spliced beside the seal's own statements and
        // spells neither the founding nor the record write.
        pub fn instantiate(&mut self) {
            Token::__record(0);
            let _ = Token::__found(Quantity::from_subunits(5));
        }
    }
}

fn main() {}
