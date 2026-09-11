use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[error]
    enum Error {
        Empty,
    }

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn drain(&mut self) -> Result<Quantity, Error> {
            self.poll()
        }

        // A helper yields its tail: spliced into `drain`, this `?` would
        // return from the export on the error arm, and a caller matching
        // on the helper's `Result` would never see `Err`.
        fn poll(&self) -> Result<Quantity, Error> {
            let held = self.held.get();
            let rest = held.try_sub(held).ok_or(Error::Empty)?;
            Ok(rest)
        }
    }
}

fn main() {}
