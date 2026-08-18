use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    #[config]
    struct Settings {
        base: Address,
        quote: Address,
    }

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            let settings = self.config().locked();
            let (half, rest) = funds.split(Quantity::ZERO.ratio_to(Quantity::ZERO).unwrap());
            self.vault(settings.base).put(half);
            self.vault(settings.quote).put(rest);
        }
    }
}

fn main() {}
