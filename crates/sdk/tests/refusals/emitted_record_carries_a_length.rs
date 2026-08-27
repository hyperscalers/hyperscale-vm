//! An event's payload encodes into a stack buffer, so every field is
//! fixed-width. The refusal is the codec's own — a `Vec<u8>` field
//! fails the infallible-encoding bound on the record's own line, before
//! the macro has an opinion.
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[record]
    #[derive(Clone)]
    struct Tally {
        count: u64,
        note: Vec<u8>,
    }

    #[event]
    struct Tallied(Tally);

    #[state]
    struct Contract {
        latest: Cell<Option<Tally>>,
    }

    impl Contract {
        pub fn count(&mut self, n: u64) {
            let tally = Tally {
                count: n,
                note: Vec::new(),
            };
            self.latest.set(Some(tally.clone()));
            Tallied(tally).emit();
        }
    }
}

fn main() {}
