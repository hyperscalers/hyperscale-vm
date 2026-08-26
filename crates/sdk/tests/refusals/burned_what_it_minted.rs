use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[resource(non_fungible, grants(mint = self, burn = self))]
    struct Seat {
        holder: u64,
    }

    #[state]
    struct Contract {
        noted: Cell<u64>,
    }

    impl Contract {
        pub fn churn(&mut self, holder: u64) {
            self.noted.set(holder);
            Seat::burn(Seat::mint(1, Seat { holder }));
        }
    }
}

fn main() {}
