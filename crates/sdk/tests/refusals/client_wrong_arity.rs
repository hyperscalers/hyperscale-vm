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

// `deposit` takes the funds it credits, and a wrapper's arity is the
// method's.
fn call(builder: &mut TypedBuilder<'_>, pool: contract::client::Contract) -> Result<(), TypedError> {
    pool.deposit(builder)
}

fn main() {}
