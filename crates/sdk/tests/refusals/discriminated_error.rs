use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {
    }

    // A hand-picked code: the table would file this variant at 0 while
    // the decline crossed as 7, a code the table cannot name.
    #[error]
    enum Refusal {
        TooSmall = 7,
    }

    impl Contract {
        pub fn check(&self) -> Result<(), Refusal> {
            Err(Refusal::TooSmall)
        }
    }
}

fn main() {}
