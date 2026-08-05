use hyperscale_hbor::{Hbor, HborMerkle};

#[derive(Hbor, HborMerkle)]
#[hbor(merkle_domain = "")]
struct Transfer {
    from: [u8; 32],
    to: [u8; 32],
}

fn main() {}
