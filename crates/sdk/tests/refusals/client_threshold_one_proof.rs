use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{Proof, TypedBuilder, TypedError};

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        chair: Address,
        deputy: Address,
        third: Address,
    }

    #[state]
    struct Contract {
        fee: Cell<Quantity>,
    }

    impl Contract {
        #[requires(n_of(2, config.chair, config.deputy, config.third))]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }
    }
}

// A threshold is met by a set, and which claims meet it is the caller's
// to choose — so the wrapper takes the set rather than one proof it
// would have to guess the sufficiency of.
fn call(
    builder: &mut TypedBuilder<'_>,
    board: contract::client::Contract,
    proof: Proof,
) -> Result<(), TypedError> {
    board.set_fee(builder, proof, 100_u128)
}

fn main() {}
