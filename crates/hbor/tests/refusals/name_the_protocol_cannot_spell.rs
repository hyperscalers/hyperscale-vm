use hyperscale_hbor::{Hbor, HborShape};

#[derive(Hbor, HborShape)]
struct Wide {
    a_field_whose_name_runs_past_the_sixty_four_bytes_a_published_name_may_occupy: u8,
}

#[derive(Hbor, HborShape)]
struct Outside {
    café: u8,
}

#[derive(Hbor, HborShape)]
enum Variants {
    Ünmarked(u8),
}

fn main() {}
