use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {
    }

    // The first thing an author coming from `thiserror` tries: data on
    // the refusal. It crosses the boundary as a bare code, so the table
    // holds names alone.
    #[error]
    enum Refusal {
        TooSmall { got: u64 },
    }

    impl Contract {
        pub fn check(&self) -> Result<(), Refusal> {
            Err(Refusal::TooSmall { got: 3 })
        }
    }
}

fn main() {}
