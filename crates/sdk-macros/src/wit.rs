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

use hyperscale_vm_effects::ADDRESS_WORDS;

use crate::mode::HandleMode;

/// What a world names the bucket resource, and why not `bucket`.
///
/// An author's module already imports the vocabulary's own `Bucket`, and
/// the generated type would collide with it — the same collision the
/// address record is aliased around, and the same answer. The resource is
/// one type either way; only the name a body would see changes.
const BUCKET: &str = "kernel-bucket";

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
    Handle(HandleMode),
    /// A borrow of the run covering one `for-each` site's expansions, at
    /// the same mode a single access through it would materialise.
    Run(HandleMode),
    /// A `u64` the guest reads as it stands.
    Scalar,
    /// A `bool`: the verdict of the guard on a branch's clauses, which
    /// the guest branches on rather than recomputing the condition.
    Flag,
    /// The world's `address` record, rebuilt as an [`Address`] in the
    /// export's prologue.
    ///
    /// [`Address`]: hyperscale_vm_sdk::Address
    Address,
    /// A byte list the guest decodes into the named Rust type.
    Cell(Box<syn::Type>),
    /// A list of non-fungible instance ids, which crosses as the ids it
    /// is rather than as a framing the guest would have to decode.
    Ids,
    /// `own<bucket>`: a value edge the call transfers to the guest.
    Bucket,
    /// `borrow<issuer>`: this invocation's authority to create value.
    Issuer,
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
    /// How many value edges the method hands back, in output order.
    pub outputs: usize,
    /// Whether the method answers with a value beside its edges.
    pub answers: bool,
    /// Whether the method carries an error arm.
    pub declines: bool,
}

impl Shape {
    /// The type as the component's own signature spells it.
    fn wit(&self) -> String {
        match self {
            Self::Handle(resource) => format!("borrow<{}>", resource.world_name()),
            Self::Run(resource) => format!("borrow<{}-run>", resource.world_name()),
            Self::Scalar => "u64".to_owned(),
            Self::Flag => "bool".to_owned(),
            Self::Address => "kernel-address".to_owned(),
            Self::Cell(_) => "list<u8>".to_owned(),
            Self::Ids => "list<u64>".to_owned(),
            Self::Bucket => format!("own<{BUCKET}>"),
            Self::Issuer => "borrow<issuer>".to_owned(),
        }
    }
}

/// Whether any export takes one of the world's own value records.
fn takes_values(exports: &[Export]) -> bool {
    exports
        .iter()
        .flat_map(|export| &export.params)
        .any(|param| matches!(param.shape, Shape::Address))
}

/// The kernel types a world has to name before its exports can use them:
/// the resources they borrow.
///
/// The world's own value records are not among them — they are declared
/// here rather than imported, for the reason [`document`] gives.
fn imported(exports: &[Export]) -> Vec<&'static str> {
    let mut named: Vec<&'static str> = Vec::new();
    // A produced edge names the resource too, even where no parameter
    // does: what an export hands back is an owned handle of it.
    if exports.iter().any(|export| export.outputs > 0) {
        named.push("bucket");
    }
    for export in exports {
        for param in &export.params {
            let resource = match param.shape {
                Shape::Handle(resource) => resource.world_name(),
                Shape::Run(resource) => resource.run_name(),
                Shape::Bucket => "bucket",
                Shape::Issuer => "issuer",
                _ => continue,
            };
            if !named.contains(&resource) {
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
         import hyperscale:kernel/math;\n    \
         import hyperscale:kernel/env;\n    \
         import hyperscale:kernel/crypto;\n    \
         import hyperscale:kernel/events;\n",
    );
    let imported = imported(exports);
    if !imported.is_empty() {
        let named: Vec<String> = imported
            .iter()
            .map(|resource| {
                if *resource == "bucket" {
                    format!("bucket as {BUCKET}")
                } else {
                    (*resource).to_owned()
                }
            })
            .collect();
        let _ = writeln!(
            out,
            "    use hyperscale:kernel/state.{{{}}};",
            named.join(", ")
        );
    }
    if takes_values(exports) {
        // Declared here rather than imported from the kernel interface,
        // and not for want of a home: `wit-bindgen` generates a type only
        // where a signature names one, so a record no import mentions is
        // one the SDK's bindings would not carry and a `with` mapping
        // could not resolve. Records are structural, so this is the same
        // type either way — and a value record is the export surface's,
        // which is what this document is.
        let [a, b, c, d] = ADDRESS_WORDS;
        let _ = write!(
            out,
            "\n    /// A global object's address, as its four 64-bit words.\n    \
             record kernel-address {{\n        \
             /// Bytes 0..8, little-endian.\n        {a}: u64,\n        \
             /// Bytes 8..16.\n        {b}: u64,\n        \
             /// Bytes 16..24.\n        {c}: u64,\n        \
             /// Bytes 24..32.\n        {d}: u64,\n    }}\n\n",
        );
    }
    for export in exports {
        let params = export
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name, p.shape.wit()))
            .collect::<Vec<_>>()
            .join(", ");
        // A method's results are its answer and its edges: one of
        // either on its own, and the tuple the profile admits for any
        // other count. The answer leads, so what follows is edges
        // whether or not one is there.
        let mut returns: Vec<String> = Vec::new();
        if export.answers {
            returns.push("list<u8>".to_owned());
        }
        returns.extend(std::iter::repeat_n(
            format!("own<{BUCKET}>"),
            export.outputs,
        ));
        let handed = match returns.as_slice() {
            [] => String::new(),
            [one] => one.clone(),
            several => format!("tuple<{}>", several.join(", ")),
        };
        let result = match (handed.is_empty(), export.declines) {
            (true, false) => String::new(),
            (true, true) => " -> result<_, u32>".to_owned(),
            (false, false) => format!(" -> {handed}"),
            (false, true) => format!(" -> result<{handed}, u32>"),
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
