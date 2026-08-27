use hyperscale_vm_sdk::blueprint;

#[blueprint(principals)]
mod contract {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Contract {
        presented: Cell<u64>,
    }

    impl Contract {
        // The kernel makes every read a presenting gate is about, so a
        // conditional body is the authorizing gate's alone.
        #[proves(badge)]
        pub fn present(&mut self, badge: Address) {
            self.presented.set(1);
        }
    }
}

fn main() {}
