use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[error]
    enum Error {
        Empty,
    }

    type Fallible<T> = Result<T, Error>;

    #[state]
    struct Contract {
        held: Cell<Quantity>,
    }

    impl Contract {
        pub fn drain(&mut self) -> Result<Quantity, Error> {
            let rest = self.poll()?;
            Ok(rest)
        }

        // A `?` is rewritten against the carrier the return type spells,
        // and an alias spells neither.
        fn poll(&self) -> Fallible<Quantity> {
            let held = self.held.get();
            let rest = held.try_sub(held).ok_or(Error::Empty)?;
            Ok(rest)
        }
    }
}

fn main() {}
