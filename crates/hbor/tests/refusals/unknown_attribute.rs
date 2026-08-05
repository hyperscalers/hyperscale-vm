use hyperscale_hbor::Hbor;

#[derive(Hbor)]
struct Header {
    #[hbor(flatten)]
    height: u64,
}

fn main() {}
