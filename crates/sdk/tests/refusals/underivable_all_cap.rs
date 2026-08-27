use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod shelf {
    use hyperscale_vm_sdk::state::Ordered;

    #[state]
    struct Shelf {
        entries: Ordered<u64>,
    }

    impl Shelf {
        // The cap is priced, so `all` keeps it stated: the sentinels of
        // the spelled range are what it drops, never the bound.
        pub fn peek(&mut self, cap: u64) {
            let entries = self.entries.all(cap.count_ones().into());
            let _ = entries.count();
        }
    }
}

fn main() {}
