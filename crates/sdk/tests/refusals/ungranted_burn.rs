use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::state::Bucket;

    #[resource(grants(mint = self))]
    struct Ungranted;

    #[state]
    struct Contract {}

    impl Contract {
        pub fn retire(&mut self, funds: Bucket) {
            Ungranted::burn(funds);
        }
    }
}

fn main() {}
