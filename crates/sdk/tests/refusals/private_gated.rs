use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    #[state]
    struct Contract {
    }

    impl Contract {
        // Forgetting `pub` is the classic slip: only public methods
        // lower, and the attribute would be stripped with nothing said.
        #[requires(self)]
        fn shutdown(&mut self) {}
    }
}

fn main() {}
