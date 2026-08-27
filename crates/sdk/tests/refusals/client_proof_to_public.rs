use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{Proof, TypedBuilder, TypedError};

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn deposit(&mut self, funds: Bucket) {
            self.vault(funds.resource()).put(funds);
        }

        #[requires(self)]
        pub fn withdraw(&mut self, resource: hyperscale_vm_sdk::Address, amount: Quantity) -> Bucket {
            self.vault(resource).reserve(amount)
        }
    }
}

// No wrapper takes anything to present: evidence is the builder's to
// resolve and an enclosing `presenting` scope's to carry, so a proof
// handed to any wrapper has no parameter to land in.
fn call(
    builder: &mut TypedBuilder<'_>,
    pool: contract::client::Contract,
    proof: Proof,
    funds: hyperscale_vm_sdk::client::Bucket,
) -> Result<(), TypedError> {
    pool.deposit(builder, proof, funds)
}

fn main() {}
