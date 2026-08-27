use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod contract {
    // The macro matches types by their last path segment, so this
    // would bind wherever the real `Bucket` does.
    struct Bucket;

    impl Contract {
        pub fn touch(&mut self) {}
    }
}

fn main() {}
