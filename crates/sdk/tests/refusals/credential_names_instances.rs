use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[resource(non_fungible, initial(0))]
    struct License;

    #[resource(grants(withdraw = held(issued(License, 0))))]
    struct Token;

    #[state]
    struct Contract {}

    impl Contract {}
}

fn main() {}
