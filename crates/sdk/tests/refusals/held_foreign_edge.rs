use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, NfBucket};

    #[resource(non_fungible)]
    struct Seat {
        holder: u64,
    }

    #[resource(non_fungible, grants(mint = self))]
    struct Pass {
        holder: u64,
    }

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        pub fn look(&mut self, holder: u64) -> NfBucket {
            let pass = Pass::mint(1, Pass { holder });
            if let Some(seat) = Seat::held(&pass) {
                self.noted.set(seat.holder);
            }
            pass
        }
    }
}

fn main() {}
