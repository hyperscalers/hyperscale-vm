use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Drawn, OrderKey, Seal, Unordered};

    #[state]
    struct Contract {
        entrants: Unordered<Address>,
        round: Cell<Option<Seal>>,
        first: Cell<Address>,
        second: Cell<Address>,
    }

    impl Contract {
        pub fn settle(&mut self, cap: u64) {
            let Drawn::Ready(draw) = self.round.open() else {
                return;
            };
            let window = self.entrants.sweep(OrderKey::at(0, 0), cap);
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
