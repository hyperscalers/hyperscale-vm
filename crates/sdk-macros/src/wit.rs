//! The world a package's guest is generated against.
//!
//! Synthesised rather than authored, from the same walk that fixed the ABI
//! binding: an export's parameter list *is* the binding, so a world
//! written beside the metadata could only ever repeat it or contradict it.
//!
//! The kernel package travels inside the document as a nested package, so
//! a contract crate vendors no WIT of its own and resolves
//! `hyperscale:kernel` from the one copy the SDK holds. What the generated
//! bindings must not do is generate the kernel interfaces a second time —
//! two Rust types for one resource cannot be handed to the same accessor —
//! which is what the `with` mapping in [`crate::guest`] settles.

use std::fmt::Write as _;

/// The vendored kernel interface, carried into every synthesised world.
///
/// Read from the SDK's single copy rather than a second one beside the
/// macro. A package that drifted from the interface it imports could
/// not link, and two copies is how the drift starts.
const KERNEL: &str = include_str!("../../sdk/wit/deps/kernel/kernel.wit");

/// What one export parameter is, on both sides of the boundary.
#[derive(Clone, Debug)]
pub enum Shape {
    /// A borrow of the kernel resource the clause's mode materialises.
    Handle(&'static str),
    /// A `u64` the guest reads as it stands.
    Scalar,
    /// A byte list the guest decodes into the named Rust type.
    Cell(Box<syn::Type>),
}

/// One parameter of a generated export.
#[derive(Clone, Debug)]
pub struct Param {
    /// The parameter's name in the component type.
    pub name: String,
    /// What it carries.
    pub shape: Shape,
}

/// One generated export.
#[derive(Clone, Debug)]
pub struct Export {
    /// The published method name, which is what a manifest node writes.
    pub name: String,
    /// The parameters, in the order the binding builds them.
    pub params: Vec<Param>,
    /// Whether the method returns a value at all.
    pub returns: bool,
    /// Whether the method carries an error arm.
    pub declines: bool,
}

impl Shape {
    /// The type as the component's own signature spells it.
    fn wit(&self) -> String {
        match self {
            Self::Handle(resource) => format!("borrow<{resource}>"),
            Self::Scalar => "u64".to_owned(),
            Self::Cell(_) => "list<u8>".to_owned(),
        }
    }
}

/// The resources a world has to name before its exports can borrow them.
fn borrowed(exports: &[Export]) -> Vec<&'static str> {
    let mut named: Vec<&'static str> = Vec::new();
    for export in exports {
        for param in &export.params {
            if let Shape::Handle(resource) = param.shape
                && !named.contains(&resource)
            {
                named.push(resource);
            }
        }
    }
    named.sort_unstable();
    named
}

/// The whole WIT document a package's bindings are generated from.
///
/// One document rather than a file tree, because a contract crate has no
/// WIT of its own to put a tree in: the world is a function of the
/// bodies above it, and it is regenerated whenever they change.
#[must_use]
pub fn document(world: &str, exports: &[Export]) -> String {
    let mut out = String::from("package contract:derived;\n\n");
    let _ = writeln!(out, "world {world} {{");
    out.push_str(
        "    import hyperscale:kernel/state;\n    \
         import hyperscale:kernel/env;\n    \
         import hyperscale:kernel/crypto;\n    \
         import hyperscale:kernel/events;\n",
    );
    let borrowed = borrowed(exports);
    if !borrowed.is_empty() {
        let _ = writeln!(
            out,
            "    use hyperscale:kernel/state.{{{}}};",
            borrowed.join(", ")
        );
    }
    for export in exports {
        let params = export
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name, p.shape.wit()))
            .collect::<Vec<_>>()
            .join(", ");
        let result = match (export.returns, export.declines) {
            (true, true) => " -> result<list<u8>, u32>",
            (true, false) => " -> list<u8>",
            (false, true) => " -> result<_, u32>",
            (false, false) => "",
        };
        let _ = writeln!(out, "    export {}: func({params}){result};", export.name);
    }
    out.push_str("}\n\n");
    // The kernel rides along as a nested package: one copy of the
    // interface, reachable from a crate that vendors nothing.
    let kernel = KERNEL.replacen("package hyperscale:kernel;", "", 1);
    let _ = write!(out, "package hyperscale:kernel {{\n{kernel}\n}}\n");
    out
}
