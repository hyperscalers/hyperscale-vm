use hyperscale_vm_sdk::blueprint;

macro_rules! credit {
    ($contract:expr => $addr:expr) => {
        let _ = $contract.vault($addr);
    };
}

#[blueprint]
mod contract {
    use hyperscale_vm_sdk::Address;
    

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn wrapped(&mut self, a: Address) {
            credit!(self => a);
        }
    }
}

fn main() {}
