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

    impl Contract {
        pub fn count(&mut self) {
            let total = self.count.get() + 1;
            self.count.set(total);
            // The event is a value here, and the walk cannot read which
            // event a value is — so nothing prices this emit.
            let event = Counted { total };
            event.emit();
        }
    }
}

fn main() {}
