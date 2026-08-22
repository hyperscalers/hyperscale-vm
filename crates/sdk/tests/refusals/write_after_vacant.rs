use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[record]
    #[derive(Clone)]
    struct Mark {
        n: u64,
    }

    #[state]
    struct Contract {
        mark: Cell<Option<Mark>>,
    }

    impl Contract {
        pub fn go(&mut self, n: u64) {
            self.mark.vacant();
            self.mark.set(Some(Mark { n }));
        }
    }
}

fn main() {}
