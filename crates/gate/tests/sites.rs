//! What an export may put a `for-each` site in, refused at publish.
//!
//! A loop's site is a capability parameter like any other: it names one
//! site of one loop, and nothing a value crosses as can stand in its
//! place. A binding that put one somewhere else is a disagreement
//! between a package's code and its signature that would otherwise
//! surface at invocation, through whatever error channel the runtime it
//! met happened to have.

use hyperscale_vm_effects::{
    AbiParam, Clause, Expr, MethodSignature, ModeExpr, PackageMetadata, ParamType, SlotRef,
    TargetExpr, package_slot, seal_clauses,
};
use hyperscale_vm_gate::{admit_package, attach_metadata};
use hyperscale_vm_types::Moves;
use wat::parse_str;

/// A module whose one export takes `param`: an `i32` for a site the
/// binding borrows, or an `i64` for the scalar a derived value crosses
/// as.
fn taking(resource: Option<&str>) -> Vec<u8> {
    let core = if resource.is_some() { "i32" } else { "i64" };
    let source = format!(
        "(module\n  (memory (export \"memory\") 1 1)\n  \
         (func (export \"m\") (param {core}))\n  \
         (func (export \"instantiate\")))"
    );
    parse_str(&source).expect("the module assembles")
}

/// One `for-each` over a caller's list, writing a cell the element keys,
/// with `abi` as the method's whole binding.
fn spreading(abi: Vec<AbiParam>) -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "instantiate".into(),
        MethodSignature {
            effects: seal_clauses(),
            ..MethodSignature::default()
        },
    );
    metadata.methods.insert(
        "m".into(),
        MethodSignature {
            params: vec![ParamType::Ids],
            abi,
            effects: vec![Clause::ForEach {
                guard: None,
                list: Expr::Arg(0),
                body: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotRef::Fixed(package_slot(0)),
                        material: vec![Expr::Binding(0)],
                    }),
                    mode: ModeExpr::Write { moves: Moves::Both },
                    denomination: None,
                }],
            }],
            ..MethodSignature::default()
        },
    );
    metadata
}

#[test]
fn a_site_parameter_is_held_to_its_width() {
    // A site crosses as its index, and a derived value as a scalar or a
    // register's length: an `i32` takes either, and which it is the
    // kernel judges at every operation. What the export type does say
    // is the width, so a handle bound to a scalar parameter is refused
    // where every other capability parameter's mismatch is.
    let artifact = attach_metadata(
        &taking(None),
        &spreading(vec![AbiParam::Handle { clause: 0, site: 0 }]),
    )
    .expect("attaches");
    let refused = admit_package(&artifact).expect_err("a handle cannot fill a scalar");
    assert_eq!(refused.method.as_deref(), Some("m"), "{refused}");
    assert!(refused.message.contains("capability handle"), "{refused}");

    // The same binding fills a parameter of its own width, and so does a
    // derived value of either width.
    for (module, abi) in [
        (
            taking(Some("site")),
            vec![AbiParam::Handle { clause: 0, site: 0 }],
        ),
        (taking(Some("site")), vec![AbiParam::Derived(Expr::Arg(0))]),
        (taking(None), vec![AbiParam::Derived(Expr::Arg(0))]),
    ] {
        let artifact = attach_metadata(&module, &spreading(abi)).expect("attaches");
        assert!(admit_package(&artifact).is_ok());
    }
}
