use hyperscale_hbor::{Hbor, HborMerkle};

#[derive(Hbor, HborMerkle)]
#[hbor(transparent)]
struct ValidatorId(u64);

fn main() {}
