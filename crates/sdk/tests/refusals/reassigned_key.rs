use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Keyed;

    #[state]
    struct Contract {
        tab: Keyed<u64>,
    }

    impl Contract {
        pub fn rebound(&mut self, flag: u64, a: Address, b: Address) {
            let mut key = a;
            if flag == 0 {
                key = b;
            }
            self.tab.at(key).set(1);
        }
    }
}

fn main() {}
