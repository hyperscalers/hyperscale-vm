use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;

    #[resource(grants(mint = self))]
    struct Ungranted;

    #[state]
    struct Contract {}

    impl Contract {
        pub fn stop(&mut self, holder: Address) {
            Ungranted::halt(holder);
        }
    }
}

fn main() {}
