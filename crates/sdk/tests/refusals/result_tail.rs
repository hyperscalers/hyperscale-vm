use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[error]
    enum Error {
        Empty,
        Stale,
    }

    #[state]
    struct Contract {
        held: Cell<Quantity>,
        seen_at: Cell<u64>,
    }

    impl Contract {
        /// A helper's fallible result, handed back as it stands.
        pub fn drain(&mut self) -> Result<Quantity, Error> {
            self.poll()
        }

        /// A unit payload, handed back as it stands: answers nothing,
        /// as `Ok(())` would.
        pub fn check(&mut self, now: u64) -> Result<(), Error> {
            self.carried(now)
        }

        /// A conditional over the two arms.
        pub fn branched(&mut self) -> Result<Quantity, Error> {
            if self.held.get().is_zero() {
                Err(Error::Empty)
            } else {
                Ok(self.held.get())
            }
        }

        /// A match over a helper's result.
        pub fn matched(&mut self) -> Result<Quantity, Error> {
            match self.poll() {
                Ok(held) => Ok(held),
                Err(error) => Err(error),
            }
        }

        fn poll(&self) -> Result<Quantity, Error> {
            let held = self.held.get();
            if held.is_zero() {
                return Err(Error::Empty);
            }
            Ok(held)
        }

        fn carried(&self, now: u64) -> Result<(), Error> {
            if self.seen_at.get() < now {
                return Err(Error::Stale);
            }
            Ok(())
        }
    }
}

fn main() {}
