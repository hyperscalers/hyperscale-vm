use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    // Not an `#[error]` enum: it holds no place in the error table, so
    // a decline through it has no code to cross the boundary as.
    enum Refusal {
        TooSmall,
    }

    #[state]
    struct Contract {
    }

    impl Contract {
        pub fn check(&self) -> Result<(), Refusal> {
            Err(Refusal::TooSmall)
        }
    }
}

fn main() {}
