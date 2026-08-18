use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Quantity;

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn conjure(&mut self, holder: Address) {
            self.vault(holder).set(Quantity::from_subunits(1_000));
        }
    }
}

fn main() {}
