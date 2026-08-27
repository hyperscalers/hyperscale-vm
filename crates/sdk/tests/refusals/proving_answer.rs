use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        uses: Cell<u64>,
    }

    impl Contract {
        // A proving call is evidence, never a value: a composer reads
        // the node for the claim it minted, so there is nobody to hear
        // an answer.
        #[proves(self)]
        pub fn pass(&mut self) -> u64 {
            let used = self.uses.get() + 1;
            self.uses.set(used);
            used
        }
    }
}

fn main() {}
