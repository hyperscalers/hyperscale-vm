use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[resource(non_fungible, grants(freeze = self))]
    struct AdminBadge;

    #[resource(grants(recall = issued(AdminBadge, 0)))]
    struct Token;

    #[state]
    struct Contract {}

    impl Contract {}
}

fn main() {}
