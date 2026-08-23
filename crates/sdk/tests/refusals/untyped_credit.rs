use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Ratio};

    #[config]
    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            let settings = self.config();
            let ([part], rest) = funds.split_n(&[Ratio::of(1, 2).expect("a half")]);
            let mut laundered = vec![part, rest];
            self.vault(settings.asset).put(laundered.remove(0));
        }
    }
}

fn main() {}
