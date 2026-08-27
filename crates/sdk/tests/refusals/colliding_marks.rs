use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[resource]
    struct OwnerBadge;

    #[resource]
    #[allow(non_camel_case_types)] // the collision under kebab is the case
    struct Owner_badge;

    #[state]
    struct Contract {
        held: Cell<u64>,
    }

    impl Contract {
        pub fn noop(&mut self) {
            self.held.set(0);
        }
    }
}

fn main() {}
