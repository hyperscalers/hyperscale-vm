use hyperscale_hbor::Hbor;

#[derive(Hbor)]
#[hbor(transparent)]
struct Pair {
    left: u64,
    right: u64,
}

fn main() {}
