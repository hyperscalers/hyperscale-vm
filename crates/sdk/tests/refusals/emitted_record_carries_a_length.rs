//! A total body may not fault, so what a method under the mark emits
//! carries no length anywhere — the event itself and every declaration
//! it names. The refusal is the codec's own: a capped byte string still
//! carries a length, and fails the length-free bound on the field that
//! holds it, before the macro has an opinion.
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
        #[total]
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
