use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[config]
    struct Settings {
        rows: Vec<u64>,
    }

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        pub fn walk(&mut self) {
            for &row in &self.config().rows {
                let _held = row;
            }
            self.noted.set(1);
        }
    }
}

fn main() {}
