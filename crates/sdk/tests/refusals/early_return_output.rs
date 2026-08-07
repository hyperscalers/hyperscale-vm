use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Keyed};

    #[state]
    struct Contract {
        #[role(1)]
        vaults: Keyed<Amount>,
    }

    impl Contract {
        pub fn either(&mut self, flag: u64, a: Address, b: Address) -> Bucket {
            if flag == 0 {
                return Bucket::of(a, 1);
            }
            Bucket::of(b, 1)
        }
    }
}

fn main() {}
