use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Quantity, Vault};

    #[error]
    enum Error {
        Empty,
    }

    #[state]
    struct Contract {
        till: Keyed<Vault>,
    }

    impl Contract {
        // The helper's take is inside a `Result` the tail hands back
        // whole, so the walk never sees the edge the signature promises.
        pub fn draw(&mut self, resource: ResourceAddr) -> Result<Bucket, Error> {
            self.pull(resource)
        }

        fn pull(&mut self, resource: ResourceAddr) -> Result<Bucket, Error> {
            if self.till.at(resource).balance().is_zero() {
                return Err(Error::Empty);
            }
            Ok(self.till.at(resource).take(Quantity::from_subunits(1)))
        }
    }
}

fn main() {}
