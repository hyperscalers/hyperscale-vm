use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity, Vault};

    #[config]
    struct Settings {
        base: Address,
        quote: Address,
    }

    #[state]
    struct Contract {
        #[holds(config.base)]
        till: Vault,
        #[holds(config.quote)]
        other: Vault,
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            let (half, rest) = funds.split(Quantity::ZERO.ratio_to(Quantity::ZERO).unwrap());
            self.till.put(half);
            self.other.put(rest);
        }
    }
}

fn main() {}
