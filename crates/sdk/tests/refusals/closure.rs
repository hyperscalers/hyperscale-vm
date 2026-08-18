use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn hidden(&mut self, a: Address) {
            let credit = || self.vault(a).declared();
            credit();
        }
    }
}

fn main() {}
