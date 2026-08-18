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

        #[guarded(self)]
        pub fn withdraw(&mut self, resource: hyperscale_vm_sdk::Address, amount: Quantity) -> Bucket {
            self.vault(resource).reserve(amount)
        }
    }
}

// `deposit` admits anyone, so its wrapper takes nothing to present.
fn call(
    builder: &mut TypedBuilder<'_>,
    pool: contract::client::Contract,
    proof: Proof,
    funds: hyperscale_vm_sdk::client::Bucket,
) -> Result<(), TypedError> {
    pool.deposit(builder, proof, funds)
}

fn main() {}
