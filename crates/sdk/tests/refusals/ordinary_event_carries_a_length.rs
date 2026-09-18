//! An event an ordinary method emits carries whatever its own bound
//! admits: the payload goes into a stack buffer that bound sizes, and
//! a length inside it costs the method nothing it claims. The mark is
//! what makes a length a thing to refuse, and this method has none.
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::hbor::Capped;
    use hyperscale_vm_sdk::state::Cell;

    #[event]
    struct Tallied {
        counts: Capped<Vec<u64>, 4>,
    }

    #[state]
    struct Contract {
        latest: Cell<u64>,
    }

    impl Contract {
        pub fn count(&mut self, n: u64) {
            self.latest.set(n);
            Tallied {
                counts: Capped::from_array([n]),
            }
            .emit();
        }
    }
}

fn main() {}
