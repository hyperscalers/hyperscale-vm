//! A protocol cell named in the shape it does not have, refused at
//! publish.
//!
//! The predicate is the vocabulary's and is tested there. What this pins
//! is that a publish consults it at all — an artifact is bytes, and the
//! only thing that reads a hand-authored declaration before a block
//! carries it is this gate.

use hyperscale_vm_effects::envelope::NULLIFIER_SLOT;
use hyperscale_vm_effects::vocabulary::{AUTH, INSTANCE, RESOURCE};
use hyperscale_vm_effects::{
    AbiParam, Clause, Expr, MethodSignature, ModeExpr, PackageMetadata, ParamType, RuleExpr,
    RuleLeaf, SlotId, SlotRef, TargetExpr, Value, seal_clauses,
};
use hyperscale_vm_gate::{admit_package, attach_metadata};
use hyperscale_vm_types::{Address, AddressClass, Moves, Presence};
use wat::parse_str;

const RES: Address = Address::new([0xE1; 31], AddressClass::Resource);

/// A component exporting `m(c: borrow<capability>, amount: u64)`.
fn component() -> Vec<u8> {
    parse_str(
        r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "site" (type $wc (sub resource)))))
  (alias export $state "site" (type $wcell))
  (core module $m
    (func (export "m") (param i32 i64))
    (func (export "seal")))
  (core instance $i (instantiate $m))
  (func (export "instantiate") (canon lift (core func $i "seal")))
  (func (export "m")
    (param "c" (borrow $wcell)) (param "amount" u64)
    (canon lift (core func $i "m"))))
"#,
    )
    .expect("the component assembles")
}

/// Metadata whose one method writes `slot` under its own prefix, keyed
/// by `material`.
fn writing(slot: SlotId, material: Vec<Expr>) -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    // Every published package brings its components up through a seal of
    // its own; the case under test is the method beside it.
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
            params: vec![ParamType::U64],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Derived(Expr::Arg(0)),
            ],
            effects: vec![
                Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotRef::Fixed(slot),
                        material: material.clone(),
                    }),
                    mode: ModeExpr::Write { moves: Moves::Both },
                    denomination: None,
                },
                // The one-way door the creating slots require, as the
                // condition it now is.
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::Require(RuleLeaf::Presence {
                        target: Box::new(TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(Expr::SelfAddr),
                            slot: SlotRef::Fixed(slot),
                            material,
                        })),
                        expect: Presence::Absent,
                    }),
                },
            ],
            ..MethodSignature::default()
        },
    );
    metadata
}

fn verdict(metadata: &PackageMetadata) -> Result<(), String> {
    let artifact = attach_metadata(&component(), metadata).expect("attaches");
    admit_package(&artifact)
        .map(|_| ())
        .map_err(|error| error.0)
}

#[test]
fn a_protocol_cell_in_the_wrong_shape_does_not_publish() {
    let resource = || Expr::Literal(Value::Address(RES));

    // The stored authority cell is keyed by nothing: it is the one cell
    // its owner has, and a package writing its own is `securify`.
    assert_eq!(verdict(&writing(AUTH, vec![])), Ok(()));
    let refused = verdict(&writing(AUTH, vec![resource()]))
        .expect_err("an authority cell keyed by a resource is not one");
    assert!(refused.contains("\"m\""), "{refused}");
    assert!(refused.contains("stored authority cell"), "{refused}");

    // A record is keyed by the resource it describes, an instance's data
    // by that resource and the id.
    assert_eq!(verdict(&writing(RESOURCE, vec![resource()])), Ok(()));
    assert!(verdict(&writing(RESOURCE, vec![])).is_err());
    assert_eq!(
        verdict(&writing(INSTANCE, vec![resource(), Expr::Arg(0)])),
        Ok(())
    );
    assert!(verdict(&writing(INSTANCE, vec![resource()])).is_err());
}

#[test]
fn a_slot_no_cell_is_assigned_does_not_publish() {
    // The kernel's own cells sit under a publisher's and a signer's
    // prefix, and no signature reaches them.
    for slot in [NULLIFIER_SLOT, SlotId(0xFFFE)] {
        let refused = verdict(&writing(slot, vec![]))
            .expect_err("the kernel's own band is not a signature's to name");
        assert!(refused.contains("no cell is assigned"), "{refused}");
    }
    // Nor is the part of the vocabulary's band it has not spoken for.
    assert!(verdict(&writing(SlotId(15), vec![])).is_err());
    // A package's own slots are its own business.
    assert_eq!(verdict(&writing(SlotId(16), vec![])), Ok(()));
}
