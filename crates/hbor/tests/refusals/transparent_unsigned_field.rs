use hyperscale_hbor::Hbor;

#[derive(Hbor)]
#[hbor(transparent)]
struct Wrapper(#[hbor(unsigned)] Vec<u8>);

fn main() {}
