//! An export borrowing the handle its clause does not materialize,
//! refused at publish.
//!
//! A cell that says what it holds gets the handle value moves through,
//! and a cell that says nothing gets the one bytes are written to. Which
//! a clause materializes is a pure function of the declaration, so an
//! export taking the other is a package whose code and signature part
//! company — and the disagreement surfaces at invocation, through
//! whatever error channel each runtime happens to have. Refused here,
//! where the verdict is one.

use hyperscale_vm_effects::{
    AbiParam, Address, AddressClass, Clause, Expr, MethodSignature, ModeExpr, PackageMetadata,
    ParamType, Presence, TargetExpr, Value, package_slot,
};
use hyperscale_vm_gate::{admit_package, attach_metadata};
use wat::parse_str;

/// A component whose one export borrows `resource`, named as the state
/// interface exports it.
fn borrowing(resource: &str) -> Vec<u8> {
    let source = format!(
        r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "{resource}" (type $c (sub resource)))))
  (alias export $state "{resource}" (type $cell))
  (core module $m
    (func (export "m") (param i32)))
  (core instance $i (instantiate $m))
  (func (export "m") (param "c" (borrow $cell))
    (canon lift (core func $i "m"))))
"#
    );
    parse_str(&source).expect("the component assembles")
}

/// One clause on the package's own slot, denominated or not.
fn declaring(holds_value: bool) -> PackageMetadata {
    let resource = || {
        Expr::Literal(Value::Address(Address::new(
            [0xE1; 31],
            AddressClass::Resource,
        )))
    };
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "m".into(),
        MethodSignature {
            params: vec![ParamType::U64],
            abi: vec![AbiParam::Handle(0)],
            effects: vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: package_slot(0),
                    material: if holds_value {
                        vec![resource()]
                    } else {
                        vec![]
                    },
                }),
                mode: ModeExpr::Write {
                    requires: Presence::Either,
                },
                denomination: holds_value.then(|| Box::new(resource())),
            }],
            ..MethodSignature::default()
        },
    );
    metadata
}

#[test]
fn an_export_borrowing_the_other_handle_does_not_publish() {
    // Each says what it holds, and takes the handle that follows.
    for (holds_value, wanted) in [(true, "amount-cell"), (false, "write-cell")] {
        let artifact =
            attach_metadata(&borrowing(wanted), &declaring(holds_value)).expect("attaches");
        assert!(
            admit_package(&artifact).is_ok(),
            "a {wanted} clause borrowing a {wanted}"
        );
    }

    // And each refuses the other's, naming the method and both types.
    for (holds_value, borrowed, materialised) in [
        (true, "write-cell", "amount-cell"),
        (false, "amount-cell", "write-cell"),
    ] {
        let artifact =
            attach_metadata(&borrowing(borrowed), &declaring(holds_value)).expect("attaches");
        let refused = admit_package(&artifact)
            .expect_err("an export cannot borrow the handle its clause does not make");
        assert!(refused.0.contains("\"m\""), "{}", refused.0);
        assert!(refused.0.contains(borrowed), "{}", refused.0);
        assert!(refused.0.contains(materialised), "{}", refused.0);
    }
}
