use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[resource(non_fungible, initial(0))]
    struct Seat {
        operator: u64,
    }

    #[state]
    struct Contract {}

    impl Contract {}
}

fn main() {}
