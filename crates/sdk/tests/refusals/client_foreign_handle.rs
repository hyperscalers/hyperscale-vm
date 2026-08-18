use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{TypedBuilder, TypedError};

#[blueprint]
mod pool {
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Vault};

    #[state]
    struct Pool {
        #[slot(1)]
        vaults: Keyed<Vault>,
    }

    impl Pool {
        pub fn deposit(&mut self, funds: Bucket) {
            self.vaults.at(funds.resource()).put(funds);
        }
    }
}

#[blueprint]
mod book {
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Vault};

    #[state]
    struct Book {
        #[slot(1)]
        vaults: Keyed<Vault>,
    }

    impl Book {
        pub fn offer(&mut self, funds: Bucket) {
            self.vaults.at(funds.resource()).put(funds);
        }
    }
}

// A handle carries which package its address runs, so a book's method is
// not something a pool answers.
fn call(
    builder: &mut TypedBuilder<'_>,
    here: pool::client::Pool,
    funds: hyperscale_vm_sdk::client::Bucket,
) -> Result<(), TypedError> {
    here.offer(builder, funds)
}

fn main() {}
