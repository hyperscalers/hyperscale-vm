//! A vault's balance is not writable: value moves, and a movement is
//! the only thing that changes it. The refusal is the type's own — a
//! vault leaf satisfies no generic-write bound, so `set` has nothing to
//! bind against and the compiler answers before the macro has an
//! opinion.
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
