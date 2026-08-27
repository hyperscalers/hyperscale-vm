use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Keyed;

    #[config]
    struct Settings {
        rows: Vec<u64>,
        columns: Vec<u64>,
    }

    #[state]
    struct Contract {
        noted: Keyed<u64>,
    }

    impl Contract {
        pub fn fill(&mut self) {
            for &row in &self.config().rows {
                let _held = row;
                for &column in &self.config().columns {
                    self.noted.at(column).set(1);
                }
            }
        }
    }
}

fn main() {}
