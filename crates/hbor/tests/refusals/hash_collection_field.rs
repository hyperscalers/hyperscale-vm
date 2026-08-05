use std::collections::HashMap;

use hyperscale_hbor::Hbor;

#[derive(Hbor)]
struct Stakes {
    by_validator: HashMap<u64, u64>,
}

fn main() {}
