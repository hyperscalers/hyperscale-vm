use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    // Sixteen is the cap, and the cap binds: the widest argument tuple
    // the client tier implements, and the widest configuration a
    // creation supplies.
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
    }

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn tally(&mut self, p0: u64, p1: u64, p2: u64, p3: u64, p4: u64, p5: u64, p6: u64, p7: u64, p8: u64, p9: u64, p10: u64, p11: u64, p12: u64, p13: u64, p14: u64, p15: u64) {
            self.held.set(Quantity::from_subunits(
                u128::from(p0 + p1 + p2 + p3 + p4 + p5 + p6 + p7)
                    + u128::from(p8 + p9 + p10 + p11 + p12 + p13 + p14 + p15),
            ));
        }
    }
}

fn main() {}
