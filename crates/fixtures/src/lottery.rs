//! The lottery: a pot anyone may enter, and a winner nobody chooses.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    AbiParam, Accessibility, ComponentAddr, Expr, MethodSignature, PackageMetadata, ParamType,
    PrincipalAddr, RoleId, Totality, Value, package_role, self_child,
};
use hyperscale_vm_manifest_builder::{BucketArg, TypedBuilder, TypedError};

/// The entrant cap a draw declares: the round a single draw settles.
pub const ROUND_CAP: u32 = 64;

/// A lottery's entrants: one entry per entrant, at the entrant's hashed
/// order, so a second entry from one address lands on its own ticket.
pub const TICKETS: RoleId = package_role(0);
/// A lottery's settled round: the draw, and the entrant it selected.
pub const DRAW: RoleId = package_role(1);

/// The lottery: a pot anyone may enter, and a winner nobody chooses.
///
/// `enter(who, funds)`: one ticket at the entrant's hashed order and the
/// stake into the pot, both commutative with every other entry — two
/// people entering at once write two entries and one delta, and neither
/// waits on the other. It is public, and the authority behind an entry is
/// the funds it carries, gated upstream at the withdrawal that produced
/// them. Whoever pays may name whoever they like as the entrant, which is
/// buying somebody a ticket.
///
/// `draw()`: a fresh read of the whole entrants interval and an exclusive
/// write of the result. Public for a reason that is not laziness — the
/// draw is the transaction's randomness, and no signer chooses it, so
/// there is nothing an operator would be trusted with. What the result
/// cell records is the draw beside the entrant it selected, which is what
/// lets a reader check the winner against the block that fixed the draw
/// rather than take the package's word for it.
///
/// Paying the pot out to the winner is a later leg this package does not
/// have: what it settles is who won, which is the part randomness decides.
#[must_use]
pub fn metadata() -> PackageMetadata {
    let ticket_order = || Expr::OrderKey {
        owner: Box::new(Expr::SelfAddr),
        role: TICKETS,
        material: vec![Expr::Arg(0)],
    };
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "enter".into(),
        MethodSignature {
            totality: Totality::Fallible,
            accessibility: Accessibility::Public,
            mints: None,
            params: vec![ParamType::Address, ParamType::Bucket],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Handle(1),
                // The order is derived rather than the guest's to compute,
                // for the reason the registry's is: a hash over the
                // collection's own keying is admission's to take.
                AbiParam::Derived(ticket_order()),
                AbiParam::Derived(Expr::Arg(0)),
                AbiParam::Bucket(1),
            ],
            outputs: vec![],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Entry {
                        owner: Expr::SelfAddr,
                        collection: TICKETS,
                        material: vec![],
                        order: ticket_order(),
                    },
                    mode: ModeExpr::Write,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(
                        VAULT,
                        vec![Expr::ResourceOf(Box::new(Expr::Arg(1)))],
                    )),
                    mode: ModeExpr::Delta,
                },
            ],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "draw".into(),
        MethodSignature {
            totality: Totality::Fallible,
            accessibility: Accessibility::Public,
            mints: None,
            params: vec![],
            abi: vec![AbiParam::Handle(0), AbiParam::Handle(1)],
            outputs: vec![],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(self_child(DRAW, vec![])),
                    mode: ModeExpr::Write,
                },
                Clause::Effect {
                    target: TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: TICKETS,
                        material: vec![],
                        lo: Expr::Literal(Value::U128(0)),
                        hi: Expr::Literal(Value::U128(u128::MAX)),
                        cap: ROUND_CAP,
                    },
                    mode: ModeExpr::Read,
                },
            ],
            calls: vec![],
        },
    );
    // Index order is the contract: the guest emits 0 and 1, and these are
    // what those indexes mean.
    methods.events = vec!["entered".into(), "drawn".into()];
    methods
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Enter `who` in `lottery`'s round, staking `funds` into the pot.
///
/// Whoever composes the call names the entrant, which is what buying
/// somebody a ticket looks like: the authority behind an entry is the
/// funds, gated at the withdrawal that produced them.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `enter`.
pub fn enter(
    builder: &mut TypedBuilder<'_>,
    lottery: ComponentAddr,
    who: PrincipalAddr,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(lottery, "enter", (who, funds))?.none()
}

/// Settle `lottery`'s round on the transaction's randomness draw.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `draw`.
pub fn draw(builder: &mut TypedBuilder<'_>, lottery: ComponentAddr) -> Result<(), TypedError> {
    builder.call(lottery, "draw", ())?.none()
}
