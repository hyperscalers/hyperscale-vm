use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[requires(self)]
    enum Mode {
        Open,
        Closed,
    }

    impl Contract {
        pub fn touch(&mut self) {}
    }
}

fn main() {}
