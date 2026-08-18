use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{TypedBuilder, TypedError};

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        #[slot(1)]
        vaults: Keyed<Vault>,
    }

    impl Contract {
        pub fn deposit(&mut self, funds: Bucket) {
            self.vaults.at(funds.resource()).put(funds);
        }

        #[guarded(self)]
        pub fn withdraw(&mut self, resource: hyperscale_vm_sdk::Address, amount: Quantity) -> Bucket {
            self.vaults.at(resource).reserve(amount)
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
