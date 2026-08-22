use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, Seal};

    #[state]
    struct Contract {
        round: Cell<Option<Seal>>,
    }

    impl Contract {
        /// A seal a body built itself, on an epoch it chose. The epoch is
        /// the whole commitment, so there is no seal a body can make:
        /// `Seal` carries nothing an author can reach, and the only thing
        /// that puts one in a cell is the kernel.
        pub fn close(&mut self) {
            self.round.create(Seal(()));
        }
    }
}

fn main() {}
