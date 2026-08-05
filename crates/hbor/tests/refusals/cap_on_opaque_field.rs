use hyperscale_hbor::Hbor;

type Peers = Vec<u64>;

#[derive(Hbor)]
struct Committee {
    #[hbor(max = 4)]
    peers: Peers,
}

fn main() {}
