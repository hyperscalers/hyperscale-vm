//! An event's payload encodes into a stack buffer, so every field is
//! fixed-width. The refusal is the codec's own — a capped byte string
//! still carries a length, and fails the length-free bound on the
//! record's own line, before the macro has an opinion.
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::hbor::Bytes;
    use hyperscale_vm_sdk::state::Cell;

    #[record]
    struct Tally {
        count: u64,
        note: Bytes<8>,
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
                note: Bytes::empty(),
            };
            self.latest.set(Some(tally.clone()));
            Tallied(tally).emit();
        }
    }
}

fn main() {}
