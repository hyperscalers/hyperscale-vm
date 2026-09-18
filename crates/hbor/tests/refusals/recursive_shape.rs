use hyperscale_hbor::ShapeNode;

trait Shape {
    const NODE: &'static ShapeNode;
}

impl Shape for u8 {
    const NODE: &'static ShapeNode = &ShapeNode::U8;
}

impl<T: Shape> Shape for Option<T> {
    const NODE: &'static ShapeNode = &ShapeNode::Option(T::NODE);
}

impl<T: Shape> Shape for Box<T> {
    const NODE: &'static ShapeNode = T::NODE;
}

struct Rec {
    next: Option<Box<Rec>>,
    value: u8,
}

impl Shape for Rec {
    const NODE: &'static ShapeNode = &ShapeNode::Struct(&[
        ("next", <Option<Box<Rec>> as Shape>::NODE),
        ("value", <u8 as Shape>::NODE),
    ]);
}

fn main() {
    let _ = <Rec as Shape>::NODE;
}
