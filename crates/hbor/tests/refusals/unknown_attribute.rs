use hyperscale_hbor::Hbor;

#[derive(Hbor)]
struct Header {
    #[hbor(skip)]
    height: u64,
}

fn main() {}
