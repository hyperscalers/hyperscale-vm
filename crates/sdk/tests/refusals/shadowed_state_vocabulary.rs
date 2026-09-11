use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    // The state field kinds are read off a type's last path segment, so
    // this would bind wherever the real `Cell` does.
    struct Cell<T>(T);

    impl Contract {
        pub fn touch(&mut self) {}
    }
}

fn main() {}
