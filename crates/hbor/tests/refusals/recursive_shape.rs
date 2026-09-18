use hyperscale_hbor::{Hbor, HborShape};

#[derive(Hbor, HborShape)]
struct Rec {
    next: Option<Box<Rec>>,
    value: u8,
}

fn main() {
    let _ = <Rec as HborShape>::NODE;
}
