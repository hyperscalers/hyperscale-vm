//! Shared fixtures for the publish gates' tests.
//!
//! The target shapes more than one gate is about: a value cell and a
//! collection under the declaring instance, and the one-clause signature
//! that reaches either. The bounds gate asks what a package's tables may
//! say about them and the declaration gate asks what a clause may, so
//! both need the same shapes and neither owns them.

use hyperscale_vm_types::{Address, AddressClass};

use crate::dsl::{Clause, Expr, ModeExpr, SlotRef, TargetExpr};
use crate::signature::{MethodSignature, Totality};
use crate::types::{SlotId, Value};

/// A resource address, for a value cell to be keyed by.
pub(super) fn a_resource() -> Expr {
    Expr::Literal(Value::Address(Address::new(
        [7; 31],
        AddressClass::Resource,
    )))
}

/// A leaf under the declaring instance, at `slot` and keyed by
/// `material`.
pub(super) fn own_point(slot: SlotId, material: Vec<Expr>) -> TargetExpr {
    TargetExpr::Point(Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: SlotRef::Fixed(slot),
        material,
    })
}

/// The whole order-key space of a collection under the declaring
/// instance, at a cap no test reaches.
pub(super) fn own_interval(slot: SlotId, material: Vec<Expr>) -> TargetExpr {
    TargetExpr::Range {
        owner: Expr::SelfAddr,
        collection: SlotRef::Fixed(slot),
        material,
        lo: Expr::Literal(Value::U128(0)),
        hi: Expr::Literal(Value::U128(u128::MAX)),
        cap: Expr::Literal(Value::U64(4)),
    }
}

/// A signature declaring exactly one clause.
pub(super) fn one_clause(
    target: TargetExpr,
    mode: ModeExpr,
    denomination: Option<Expr>,
) -> MethodSignature {
    MethodSignature {
        totality: Totality::Fallible,
        effects: vec![Clause::Effect {
            reach: None,
            guard: None,
            target,
            mode,
            denomination: denomination.map(Box::new),
        }],
        ..MethodSignature::default()
    }
}
