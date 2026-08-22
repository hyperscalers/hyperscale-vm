use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Keyed;

    #[config]
    struct Settings {
        rows: Vec<u64>,
    }

    #[state]
    struct Contract {
        owed: Keyed<u64>,
    }

    impl Contract {
        pub fn fill(&mut self) {
            for &row in &self.config().rows {
                self.owed.at(row).set(row);
            }
        }
    }
}

fn main() {}
