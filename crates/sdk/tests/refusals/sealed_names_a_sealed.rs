use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[resource(non_fungible, seals(freeze = self))]
    struct AdminBadge;

    #[resource(seals(recall = issued(AdminBadge, 0)))]
    struct Token;

    #[state]
    struct Contract {}

    impl Contract {}
}

fn main() {}
