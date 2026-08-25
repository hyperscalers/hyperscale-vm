use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[resource(initial(0))]
    struct License;

    #[resource(grants(withdraw = issued(License, 0)))]
    struct Token;

    #[state]
    struct Contract {}

    impl Contract {}
}

fn main() {}
