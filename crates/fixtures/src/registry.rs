//! The name registry: the unordered-collection surface end to end.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_hbor::TypeShape;
use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::{
    AbiParam, Expr, LeafForm, MethodSignature, PackageMetadata, ParamType, SlotId, SlotKind,
    SlotRef, SlotShape, Totality, Value, package_slot,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_types::{ComponentAddr, Moves};

/// The entry cap the registry's drain declares.
pub const DRAIN_CAP: u32 = 8;

/// The registry's bindings: an unordered collection keyed by hashed name.
pub const NAMES: SlotId = package_slot(0);

/// The name registry: the unordered-collection surface end to end.
///
/// Each binding is one entry of the `NAMES` collection at the hash of its
/// name — the order arrives at the guest as a derived argument, because
/// the hash is admission's to compute. `bind` writes the binding, `check`
/// reads it and traps on a mismatch, and `drain` removes the hash order's
/// tail from a caller-named cursor, `DRAIN_CAP` entries per crank.
#[must_use]
pub fn metadata() -> PackageMetadata {
    let binding = |name_slot: u32| {
        let order = Expr::OrderKey {
            owner: Box::new(Expr::SelfAddr),
            slot: NAMES,
            material: vec![Expr::Arg(name_slot)],
        };
        (
            TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: SlotRef::Fixed(NAMES),
                material: vec![],
                order: order.clone(),
            },
            order,
        )
    };
    let mut methods = PackageMetadata::default();
    methods.state.insert(
        NAMES,
        SlotShape {
            name: "names".to_owned(),
            kind: SlotKind::Unordered,
            element: LeafForm::Value(TypeShape::U128),
            denomination: None,
        },
    );
    let (target, order) = binding(0);
    methods.methods.insert(
        "bind".into(),
        MethodSignature {
            totality: Totality::Infallible,
            issues: Vec::new(),
            params: vec![ParamType::U64, ParamType::U128],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Derived(order),
                AbiParam::Derived(Expr::Arg(1)),
            ],
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target,
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }],
            ..MethodSignature::default()
        },
    );
    let (target, _) = binding(0);
    methods.methods.insert(
        "check".into(),
        MethodSignature {
            totality: Totality::Infallible,
            issues: Vec::new(),
            params: vec![ParamType::U64, ParamType::U128],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Derived(Expr::Arg(1)),
            ],
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target,
                mode: ModeExpr::Read,
                denomination: None,
            }],
            ..MethodSignature::default()
        },
    );
    methods.methods.insert(
        "drain".into(),
        MethodSignature {
            totality: Totality::Infallible,
            issues: Vec::new(),
            params: vec![ParamType::U128],
            abi: vec![AbiParam::Handle { clause: 0, site: 0 }],
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: SlotRef::Fixed(NAMES),
                    material: vec![],
                    lo: Expr::Arg(0),
                    hi: Expr::Literal(Value::U128(u128::MAX)),
                    cap: Expr::Literal(Value::U64(u64::from(DRAIN_CAP))),
                },
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }],
            ..MethodSignature::default()
        },
    );
    methods
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Bind `name` to `value` on `registry`, overwriting any prior
/// binding.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `bind`.
pub fn bind(
    builder: &mut TypedBuilder<'_>,
    registry: ComponentAddr,
    name: u64,
    value: u128,
) -> Result<(), TypedError> {
    builder.call(registry, "bind", (name, value))?.none()
}

/// Read the binding for `name`; execution traps unless it holds
/// exactly `expected`.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `check`.
pub fn check(
    builder: &mut TypedBuilder<'_>,
    registry: ComponentAddr,
    name: u64,
    expected: u128,
) -> Result<(), TypedError> {
    builder.call(registry, "check", (name, expected))?.none()
}

/// Remove one crank's worth of bindings from `cursor` up the hash
/// order; resume from the last removed order plus one.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `drain`.
pub fn drain(
    builder: &mut TypedBuilder<'_>,
    registry: ComponentAddr,
    cursor: u128,
) -> Result<(), TypedError> {
    builder.call(registry, "drain", (cursor,))?.none()
}
