use hyperscale_hbor::{Hbor, HborMerkle};

#[derive(Hbor, HborMerkle)]
struct Transfer {
    from: [u8; 32],
    to: [u8; 32],
}

fn main() {}
