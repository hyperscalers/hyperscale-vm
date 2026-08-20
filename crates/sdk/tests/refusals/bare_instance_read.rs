use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[resource(non_fungible)]
    struct OwnerBadge;

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        pub fn note(&mut self, id: u64) {
            if let Some(badge) = OwnerBadge::filed(id) {
                let _ = badge;
                self.noted.set(id);
            }
        }
    }
}

fn main() {}
