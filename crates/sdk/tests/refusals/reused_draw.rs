use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Unordered, randomness};

    #[state]
    struct Contract {
        entrants: Unordered<Address>,
        first: Cell<Address>,
        second: Cell<Address>,
    }

    impl Contract {
        pub fn settle(&mut self, cap: u64) {
            let draw = randomness();
            let window = self.entrants.sweep(0, cap);
            if let Some(who) = window.pick(draw) {
                self.first.set(who);
            }
            if let Some(who) = window.pick(draw) {
                self.second.set(who);
            }
        }
    }
}

fn main() {}
