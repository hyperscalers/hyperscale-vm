use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Instances;

    #[resource(grants(mint = self))]
    struct Coin;

    #[state]
    struct Contract {
        #[holds(issued(Coin))]
        locker: Instances,
    }
}

fn main() {}
