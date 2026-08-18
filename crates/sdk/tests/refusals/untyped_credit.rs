use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Bucket;

    #[config]
    struct Settings {
        asset: Address,
    }

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn bank(&mut self, funds: Bucket) {
            let settings = self.config().locked();
            let (mut parts, rest) = funds.split_n(&[]);
            parts.push(rest);
            self.vault(settings.asset).put(parts.remove(0));
        }
    }
}

fn main() {}
