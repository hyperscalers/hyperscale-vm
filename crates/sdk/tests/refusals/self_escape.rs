use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Keyed, Vault};
    

    #[state]
    struct Contract {
        vaults: Keyed<Vault>,
    }

    fn helper(contract: &mut Contract, a: ResourceAddr) {
        let _ = contract.vaults.at(a).balance();
    }

    impl Contract {
        pub fn indirect(&mut self, a: ResourceAddr) {
            helper(self, a);
        }
    }
}

fn main() {}
