use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[event]
    struct Counted {
        total: u64,
    }

    #[state]
    struct Contract {
        count: Cell<u64>,
    }

    // A free function is not spliced into any method, so an emit here runs
    // under a declaration that never priced it.
    fn announce(total: u64) {
        Counted { total }.emit();
    }

    impl Contract {
        pub fn count(&mut self) {
            let total = self.count.get() + 1;
            self.count.set(total);
            announce(total);
        }
    }
}

fn main() {}
