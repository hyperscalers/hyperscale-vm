use hyperscale_hbor::Hbor;

#[derive(Hbor)]
#[hbor(signing_domain = "vote-v1")]
struct Vote {
    #[hbor(unsigned)]
    signer: [u8; 32],
    #[hbor(unsigned)]
    signature: [u8; 64],
}

fn main() {}
