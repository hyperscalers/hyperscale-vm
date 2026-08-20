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
