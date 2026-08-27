use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    // A gate sits on a method; a struct carrying one declares nothing.
    #[proves(self)]
    struct Badge;

    impl Contract {
        pub fn touch(&mut self) {}
    }
}

fn main() {}
