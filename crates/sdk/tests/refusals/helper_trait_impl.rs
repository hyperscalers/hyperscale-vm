use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    trait Ready {
        fn ready(&self) -> bool;
    }

    // A trait impl's methods are the trait's, not inlining sites. An
    // early `return` here is legal — nothing splices it — and the name it
    // shares with the inherent `ready` helper below does not shadow it.
    impl Ready for Contract {
        fn ready(&self) -> bool {
            if self.held.get().is_zero() {
                return false;
            }
            true
        }
    }

    impl Contract {
        pub fn drain(&mut self) -> Quantity {
            self.ready()
        }

        fn ready(&self) -> Quantity {
            self.held.get()
        }
    }
}

fn main() {}
