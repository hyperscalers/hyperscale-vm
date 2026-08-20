use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{TypedBuilder, TypedError};

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

// `withdraw` is guarded, so its wrapper takes the proof that acts.
fn call(
    builder: &mut TypedBuilder<'_>,
    pool: contract::client::Contract,
    resource: hyperscale_vm_sdk::Address,
) -> Result<hyperscale_vm_sdk::client::Bucket, TypedError> {
    pool.withdraw(builder, resource, 100_u128)
}

fn main() {}
