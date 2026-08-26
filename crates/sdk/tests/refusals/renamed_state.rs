use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod vault {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity};

    #[state]
    struct Ledger {
        held: Cell<Quantity>,
    }

    impl Ledger {
        pub fn deposit(&mut self, funds: Bucket) {
            self.vault(funds.resource()).put(funds);
        }
    }
}

fn main() {}
