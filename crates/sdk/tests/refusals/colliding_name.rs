use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Quantity;

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn tally(&self) -> Quantity {
            Quantity::from_subunits(0)
        }

        // A rename landing on a sibling's published name: one export per
        // name, refused at the line rather than a panic inside the
        // generated `blueprint()`.
        #[name("tally")]
        pub fn recount(&self) -> Quantity {
            Quantity::from_subunits(1)
        }
    }
}

fn main() {}
