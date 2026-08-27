use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    // A free function is ordinary code; the vocabulary reads nothing on
    // it, and the strip would otherwise eat the claim whole.
    #[total]
    fn largest(numbers: &[u64]) -> u64 {
        numbers.iter().copied().max().unwrap_or(0)
    }

    impl Contract {
        pub fn touch(&mut self) {}
    }
}

fn main() {}
