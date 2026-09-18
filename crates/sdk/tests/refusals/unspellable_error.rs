use hyperscale_vm_sdk::blueprint;

// A declined invocation crosses the boundary as a code, and the error
// table is what turns that code back into a word a wallet renders.
#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[error]
    enum Refusal {
        Épuisé,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        pub fn settle(&mut self, fee: Quantity) -> Result<(), Refusal> {
            self.fee.set(fee);
            Ok(())
        }
    }
}

fn main() {}
