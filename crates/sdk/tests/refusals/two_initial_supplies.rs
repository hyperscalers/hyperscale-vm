use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[resource(non_fungible, initial(0))]
    struct OwnerBadge;

    #[resource(initial(100))]
    struct Coupon;

    #[state]
    struct Contract {}

    impl Contract {}
}

fn main() {}
