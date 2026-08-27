use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Ratio, Vault};

    #[config]
    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
        #[holds(config.asset)]
        till: Vault,
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            let ([part], rest) = funds.split_n(&[Ratio::of(1, 2).expect("a half")]);
            let mut laundered = vec![part, rest];
            self.till.put(laundered.remove(0));
        }
    }
}

fn main() {}
