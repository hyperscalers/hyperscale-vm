use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn credit(&mut self, a: Address) {
            self.vault(a).declared_credit();
        }

        pub fn double(&mut self, a: Address) {
            self.credit(a);
            self.credit(a);
        }
    }
}

fn main() {}
