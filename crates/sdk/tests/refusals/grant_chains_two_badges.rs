use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[resource(non_fungible, grants(freeze = self))]
    struct AdminBadge;

    // Nameable: a badge carries the rules its own address folds, and
    // this one names no badge of its own.
    #[resource(grants(recall = issued(AdminBadge, 0)))]
    struct Registered;

    // Not: naming this would make the token's address fold a chain two
    // links long.
    #[resource(grants(withdraw = issued(Registered)))]
    struct Token;

    #[state]
    struct Contract {}

    impl Contract {}
}

fn main() {}
