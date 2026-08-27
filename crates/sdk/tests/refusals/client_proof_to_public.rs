use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{Proof, TypedBuilder, TypedError};

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Quantity, Vault};

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        pub fn deposit(&mut self, funds: Bucket) {
            self.till.at(funds.resource()).put(funds);
        }

        #[requires(self)]
        pub fn withdraw(&mut self, resource: ResourceAddr, amount: Quantity) -> Bucket {
            self.till.at(resource).reserve(amount)
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
