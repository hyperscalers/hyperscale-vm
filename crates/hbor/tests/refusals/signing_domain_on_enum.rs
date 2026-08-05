use hyperscale_hbor::Hbor;

#[derive(Hbor)]
#[hbor(signing_domain = "body-v1")]
enum Body {
    Call(u64),
    Publish(u64),
}

fn main() {}
