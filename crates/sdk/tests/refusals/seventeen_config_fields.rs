use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    // One past the widest tuple a creation binds.
    #[config]
    struct Terms {
        f0: u64,
        f1: u64,
        f2: u64,
        f3: u64,
        f4: u64,
        f5: u64,
        f6: u64,
        f7: u64,
        f8: u64,
        f9: u64,
        f10: u64,
        f11: u64,
        f12: u64,
        f13: u64,
        f14: u64,
        f15: u64,
        f16: u64,
    }

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn tally(&mut self) {
            self.held.set(Quantity::from_subunits(u128::from(self.config().f0)));
        }
    }
}

fn main() {}
