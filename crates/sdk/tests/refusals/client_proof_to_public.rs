use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{Proof, TypedBuilder, TypedError};

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        #[role(1)]
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
