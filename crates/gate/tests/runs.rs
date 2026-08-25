//! What an export may put a `for-each` site's run in, refused at publish.
//!
//! A run is a capability parameter like any other: it names one site of
//! one loop, and nothing a value crosses as can stand in its place. A
//! binding that put one somewhere else is a disagreement between a
//! package's code and its signature that would otherwise surface at
//! invocation, through whatever error channel the runtime it met
//! happened to have.

use hyperscale_vm_effects::{
    AbiParam, Clause, Expr, MethodSignature, ModeExpr, PackageMetadata, ParamType, TargetExpr,
    package_slot, seal_clauses,
};
use hyperscale_vm_gate::{admit_package, attach_metadata};
use wat::parse_str;

/// A component whose one export takes `param`, spelled as the state
/// interface exports the resource it borrows — or as a plain `u64`,
/// which is what a derived value crosses as.
fn taking(resource: Option<&str>) -> Vec<u8> {
    let (import, param, core) = resource.map_or_else(
        || (String::new(), "u64", "i64"),
        |resource| {
            (
                format!(
                    r#"(import "hyperscale:kernel/state" (instance $state
    (export "{resource}" (type $c (sub resource)))))
  (alias export $state "{resource}" (type $run))"#
                ),
                "(borrow $run)",
                "i32",
            )
        },
    );
    let source = format!(
        r#"
(component
  {import}
  (core module $m
    (func (export "m") (param {core}))
    (func (export "seal")))
  (core instance $i (instantiate $m))
  (func (export "instantiate") (canon lift (core func $i "seal")))
  (func (export "m") (param "r" {param})
    (canon lift (core func $i "m"))))
"#
    );
    parse_str(&source).expect("the component assembles")
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
                        slot: package_slot(0),
                        material: vec![Expr::Binding(0)],
                    }),
                    mode: ModeExpr::Write,
                    denomination: None,
                }],
            }],
            ..MethodSignature::default()
        },
    );
    metadata
}

#[test]
fn a_derived_value_does_not_fill_a_run_parameter() {
    // A run is a borrow on what the kernel owns, and a derived value is
    // a copy the declaration evaluated — so nothing about the two lines
    // up, and the mismatch is refused where every other capability
    // parameter's is.
    let artifact = attach_metadata(
        &taking(Some("site")),
        &spreading(vec![AbiParam::Derived(Expr::Arg(0))]),
    )
    .expect("attaches");
    let refused =
        admit_package(&artifact).expect_err("a derived value cannot fill a resource borrow");
    assert!(refused.0.contains("\"m\""), "{}", refused.0);
    assert!(refused.0.contains("derived"), "{}", refused.0);

    // And the binding it does fill, so the refusal above is about the
    // parameter's shape rather than about the binding.
    let artifact = attach_metadata(
        &taking(None),
        &spreading(vec![AbiParam::Derived(Expr::Arg(0))]),
    )
    .expect("attaches");
    assert!(
        admit_package(&artifact).is_ok(),
        "a derived value as a scalar"
    );
}
