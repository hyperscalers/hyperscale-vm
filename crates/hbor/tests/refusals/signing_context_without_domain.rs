use hyperscale_hbor::Hbor;

#[derive(Hbor)]
#[hbor(signing_context = u8)]
struct Message {
    height: u64,
}

fn main() {}
