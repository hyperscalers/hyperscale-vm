use hyperscale_hbor::Hbor;

#[derive(Hbor)]
enum Body {
    Empty,
    #[hbor(discriminant = 0)]
    Call(u64),
}

fn main() {}
