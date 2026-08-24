use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::{Cell, RuleBytes};

    #[state]
    struct Contract {
        held: Cell<Option<RuleBytes>>,
    }

    impl Contract {
        // One cell, required absent and required present. No committed
        // state satisfies both, so the call could never be feasible.
        pub fn both(&mut self, rule: RuleBytes) {
            let _ = self.held.existing();
            self.held.create(rule);
        }
    }
}

fn main() {}
