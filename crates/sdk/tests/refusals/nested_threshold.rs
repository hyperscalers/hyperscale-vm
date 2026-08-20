use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        chair: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        // One level past what a stored rule decodes under. Three
        // thresholds over a claim is the deepest gate there is, and the
        // macro reads that bound from the vocabulary rather than
        // restating it — so a gate the decoder would refuse never
        // reaches the decoder.
        #[requires(n_of(1, n_of(1, n_of(1, n_of(1, chair)))))]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

fn main() {}
