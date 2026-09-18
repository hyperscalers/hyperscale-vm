//! A record is written into a leaf whose width the declaration states,
//! so what it holds has to state one too. A bare collection does not,
//! and the refusal lands on the field rather than on a generated line.
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[record]
    struct Entry {
        amount: u64,
        parties: Vec<u64>,
    }

    #[state]
    struct Contract {
        latest: Cell<Option<Entry>>,
    }

    impl Contract {
        pub fn file(&mut self, amount: u64) {
            self.latest.set(Some(Entry {
                amount,
                parties: Vec::new(),
            }));
        }
    }
}

fn main() {}
