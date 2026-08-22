use hyperscale_vm_sdk::blueprint;

macro_rules! credit {
    ($contract:expr => $addr:expr) => {
        $contract.vaults.at($addr).add(0)
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
