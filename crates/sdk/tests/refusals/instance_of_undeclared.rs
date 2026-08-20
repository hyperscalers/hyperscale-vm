use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        pub fn note(&mut self, id: u64) {
            if Address::at(id).is_some() {
                self.noted.set(id);
            }
        }
    }
}

fn main() {}
