use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    

    #[state]
    struct Contract {
    }

    fn helper(contract: &mut Contract, a: Address) {
        contract.vaults.at(a).declared();
    }

    impl Contract {
        pub fn indirect(&mut self, a: Address) {
            helper(self, a);
        }
    }
}

fn main() {}
