use hyperscale_hbor::Hbor;

#[derive(Hbor)]
struct Vote {
    height: u64,
    #[hbor(unsigned)]
    signature: [u8; 64],
}

fn main() {}
