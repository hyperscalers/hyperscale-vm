use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        count: Cell<u64>,
    }

    impl Contract {
        // The configuration leaf is written by the bring-up alone; a
        // method that wrote it would make the component actual outside
        // the one node that may.
        pub fn reseal(&mut self) {
            self.__seal();
            self.count.set(1);
        }
    }
}

fn main() {}
