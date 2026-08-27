use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{TypedBuilder, TypedError};

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

// A bucket position takes an edge, and a number is not one.
fn call(builder: &mut TypedBuilder<'_>, pool: contract::client::Contract) -> Result<(), TypedError> {
    pool.deposit(builder, 100_u128)
}

fn main() {}
