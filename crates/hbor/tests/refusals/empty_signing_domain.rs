use hyperscale_hbor::Hbor;

#[derive(Hbor)]
#[hbor(signing_domain = "")]
struct Vote {
    height: u64,
}

fn main() {}
