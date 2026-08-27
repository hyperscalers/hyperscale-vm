use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod shelf {
    use hyperscale_vm_sdk::state::Ordered;

    #[state]
    struct Shelf {
        entries: Ordered<u64>,
    }

    impl Shelf {
        // A capless interval derives its cap from the moves performed
        // through it, and a read moves nothing: it walks a page somebody
        // chose, so the page is named with `range` or nothing bounds it.
        pub fn peek(&mut self) {
            let entries = self.entries.whole();
            let _ = entries.count();
        }
    }
}

fn main() {}
