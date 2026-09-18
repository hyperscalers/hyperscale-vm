use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Quantity;

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn re_count(&self) -> Quantity {
            Quantity::from_subunits(0)
        }

        // Two identifiers spelling one published name: the kebab form
        // erases case, so one export per name is refused at the line
        // rather than as a panic inside the generated `blueprint()`.
        #[allow(non_snake_case)]
        pub fn reCount(&self) -> Quantity {
            Quantity::from_subunits(1)
        }
    }
}

fn main() {}
