//! The order book: makers place asks, takers fill by price-time
//! priority.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    AbiParam, Accessibility, ComponentAddr, Expr, MethodSignature, PackageMetadata, ParamType,
    RoleId, Totality, Value, package_role, self_child,
};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, TypedBuilder, TypedError};

/// The entry cap the book's fill range declares.
pub const FILL_CAP: u32 = 64;

/// The order book's ask-side ordered collection.
pub const ASKS: RoleId = package_role(0);

/// The order book.
///
/// `place-ask(price, funds)`: insert at the computed entry key — the price
/// packed over a fresh sequence id — and escrow the maker's funds into the
/// book vault. `fill-asks(from, to, payment)`: an exclusive write over the
/// declared price interval with an entry cap, base outflow from the book's
/// escrow vault, quote inflow to it.
#[must_use]
pub fn metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "place-ask".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            params: vec![ParamType::U64, ParamType::Bucket],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Handle(1),
                AbiParam::Derived(Expr::Arg(0)),
                AbiParam::Derived(Expr::FreshId { slot: 0 }),
                AbiParam::Bucket(1),
            ],
            outputs: vec![],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Entry {
                        owner: Expr::SelfAddr,
                        collection: ASKS,
                        material: vec![],
                        order: Expr::Pack {
                            hi: Box::new(Expr::Arg(0)),
                            lo: Box::new(Expr::FreshId { slot: 0 }),
                        },
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
        "fill-asks".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            params: vec![ParamType::U64, ParamType::U64, ParamType::Bucket],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Handle(1),
                AbiParam::Handle(2),
                AbiParam::Bucket(2),
            ],
            outputs: vec![Expr::Config(0), Expr::ResourceOf(Box::new(Expr::Arg(2)))],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: ASKS,
                        material: vec![],
                        lo: Expr::Pack {
                            hi: Box::new(Expr::Arg(0)),
                            lo: Box::new(Expr::Literal(Value::U64(0))),
                        },
                        hi: Expr::Pack {
                            hi: Box::new(Expr::Arg(1)),
                            lo: Box::new(Expr::Literal(Value::U64(u64::MAX))),
                        },
                        cap: FILL_CAP,
                    },
                    mode: ModeExpr::Write,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(VAULT, vec![Expr::Config(0)])),
                    mode: ModeExpr::Delta,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(
                        VAULT,
                        vec![Expr::ResourceOf(Box::new(Expr::Arg(2)))],
                    )),
                    mode: ModeExpr::Delta,
                },
            ],
            calls: vec![],
        },
    );
    methods
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Offer `funds` on `book` at `price`, escrowed until filled.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `place-ask`.
pub fn place_ask(
    builder: &mut TypedBuilder<'_>,
    book: ComponentAddr,
    price: u64,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(book, "place-ask", (price, funds))?.none()
}

/// Spend `payment` against `book`'s asks priced within `from..=to`,
/// answering what was bought and then what of the payment was not
/// spent, in that order.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `fill-asks`.
pub fn fill_asks(
    builder: &mut TypedBuilder<'_>,
    book: ComponentAddr,
    from: u64,
    to: u64,
    payment: impl BucketArg,
) -> Result<[Bucket; 2], TypedError> {
    builder
        .call(book, "fill-asks", (from, to, payment))?
        .into_array()
}
