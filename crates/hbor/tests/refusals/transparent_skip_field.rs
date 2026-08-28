use hyperscale_hbor::Hbor;

#[derive(Hbor)]
#[hbor(transparent)]
struct Wrapper(#[hbor(skip)] Vec<u8>);

fn main() {}
