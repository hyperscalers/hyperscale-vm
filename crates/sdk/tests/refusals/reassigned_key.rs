use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn rebound(&mut self, flag: u64, a: Address, b: Address) {
            let mut key = a;
            if flag == 0 {
                key = b;
            }
            self.vault(key).declared();
        }
    }
}

fn main() {}
