use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::client::{TypedBuilder, TypedError};

#[blueprint]
mod pool {
    use hyperscale_vm_sdk::state::Bucket;

    #[state]
    struct Pool {
    }

    impl Pool {
        pub fn deposit(&mut self, funds: Bucket) {
            self.vault(funds.resource()).put(funds);
        }
    }
}

#[blueprint]
mod book {
    use hyperscale_vm_sdk::state::Bucket;

    #[state]
    struct Book {
    }

    impl Book {
        pub fn offer(&mut self, funds: Bucket) {
            self.vault(funds.resource()).put(funds);
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
