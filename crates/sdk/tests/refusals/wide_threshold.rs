use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        k01: Address,
        k02: Address,
        k03: Address,
        k04: Address,
        k05: Address,
        k06: Address,
        k07: Address,
        k08: Address,
        k09: Address,
        k10: Address,
        k11: Address,
        k12: Address,
        k13: Address,
        k14: Address,
        k15: Address,
        k16: Address,
        k17: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // One claim past the width the vocabulary admits: the branch cap
        // bounds what evaluating a stored rule can cost, and a threshold
        // past it would never decode. Refused on the line rather than at
        // the tracer, where the shape is all that is left.
        #[requires(n_of(
            1,
            config.k01,
            config.k02,
            config.k03,
            config.k04,
            config.k05,
            config.k06,
            config.k07,
            config.k08,
            config.k09,
            config.k10,
            config.k11,
            config.k12,
            config.k13,
            config.k14,
            config.k15,
            config.k16,
            config.k17
        ))]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
