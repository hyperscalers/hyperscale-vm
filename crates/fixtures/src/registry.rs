//! The name registry: the unordered-collection surface end to end.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::{
    AbiParam, Accessibility, ComponentAddr, Expr, MethodSignature, PackageMetadata, ParamType,
    RoleId, Totality, Value, package_role,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};

/// The entry cap the registry's drain declares.
pub const DRAIN_CAP: u32 = 8;

/// The registry's bindings: an unordered collection keyed by hashed name.
pub const NAMES: RoleId = package_role(0);

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
            role: NAMES,
            material: vec![Expr::Arg(name_slot)],
        };
        (
            TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: NAMES,
                material: vec![],
                order: order.clone(),
            },
            order,
        )
    };
    let mut methods = PackageMetadata::default();
    let (target, order) = binding(0);
    methods.methods.insert(
        "bind".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            issues: None,
            params: vec![ParamType::U64, ParamType::U128],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Derived(order),
                AbiParam::Derived(Expr::Arg(1)),
            ],
            effects: vec![Clause::Effect {
                target,
                mode: ModeExpr::Write,
            }],
            ..MethodSignature::default()
        },
    );
    let (target, _) = binding(0);
    methods.methods.insert(
        "check".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            issues: None,
            params: vec![ParamType::U64, ParamType::U128],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(1))],
            effects: vec![Clause::Effect {
                target,
                mode: ModeExpr::Read,
            }],
            ..MethodSignature::default()
        },
    );
    methods.methods.insert(
        "drain".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            issues: None,
            params: vec![ParamType::U128],
            abi: vec![AbiParam::Handle(0)],
            effects: vec![Clause::Effect {
                target: TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: NAMES,
                    material: vec![],
                    lo: Expr::Arg(0),
                    hi: Expr::Literal(Value::U128(u128::MAX)),
                    cap: DRAIN_CAP,
                },
                mode: ModeExpr::Write,
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
