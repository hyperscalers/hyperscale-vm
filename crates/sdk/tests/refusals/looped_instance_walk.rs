use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, NfBucket};

    #[resource(non_fungible)]
    struct Seat {
        holder: u64,
    }

    #[config]
    struct Settings {
        rows: Vec<u64>,
    }

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        pub fn survey(&mut self, seats: NfBucket) -> NfBucket {
            let mut last = 0;
            for &row in &self.config().rows {
                for held in Seat::each(&seats) {
                    last = held.holder + row;
                }
            }
            self.noted.set(last);
            seats
        }
    }
}

fn main() {}
