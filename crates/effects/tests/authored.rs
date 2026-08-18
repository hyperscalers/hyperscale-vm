//! The authored corpus, held to the rules a package is admitted under.
//!
//! Exhaustive on purpose, and an integration test on purpose: a package
//! lives with the crate that ships it, so the sweep over every package
//! has to stand where it can see them all — which is outside the crate
//! defining the rules.

use hyperscale_vm_effects::{
    Accessibility, AuthRole, CustodyClaim, Expr, PackageMetadata, Value, check_abi,
    check_declarations,
};
use hyperscale_vm_fixtures::{amm, book, lottery, splitter};
use hyperscale_vm_stdlib::staking::OWNER_BADGE;
use hyperscale_vm_stdlib::{account, staking};

/// Every authored package, in the order the exhaustive sweeps read them.
fn corpus() -> Vec<(&'static str, PackageMetadata)> {
    vec![
        ("account", account::metadata()),
        ("amm", amm::metadata()),
        ("book", book::metadata()),
        ("lottery", lottery::metadata()),
        ("splitter", splitter::metadata()),
        ("staking", staking::metadata()),
    ]
}

/// Exhaustive over the corpus: whatever a package may declare, an
/// authored one declares only its own.
#[test]
fn every_authored_signature_declares_its_own_prefix() {
    for (package, metadata) in corpus() {
        for (name, signature) in &metadata.methods {
            assert_eq!(check_declarations(signature), Ok(()), "{package}::{name}");
        }
    }
}

#[test]
fn every_authored_signature_is_well_formed() {
    // The corpus is the whole authored surface, so a rule it breaks
    // is a rule nothing else could be held to.
    for (package, metadata) in corpus() {
        for (name, signature) in &metadata.methods {
            assert_eq!(check_abi(signature), Ok(()), "{package}::{name}");
        }
    }
}

/// Who may call every authored method, as a table.
///
/// Exhaustive on purpose. `Public` is the default, so a method added
/// without a thought about its callers gets the permissive value
/// silently — and the shape that is easiest to miss moves no funds at
/// all: `securify` writes a leaf under its target's prefix and consumes
/// nothing, which is the same class as any later per-account module.
/// Adding a method breaks this list, which is the point.
fn authored_accessibility() -> Vec<(&'static str, &'static str, Accessibility)> {
    vec![
        ("account", "authorize", Accessibility::Authorizing),
        (
            "account",
            "cancel",
            Accessibility::RoleGated(AuthRole::Primary),
        ),
        (
            "account",
            "confirm",
            Accessibility::RoleGated(AuthRole::Confirmation),
        ),
        ("account", "deposit", Accessibility::Public),
        ("account", "deposit-nf", Accessibility::Public),
        (
            "account",
            "present-badge",
            Accessibility::Custodial(CustodyClaim::Fungible(Expr::Arg(0))),
        ),
        (
            "account",
            "present-instance",
            Accessibility::Custodial(CustodyClaim::Instance {
                badge: Expr::Arg(0),
                id: Expr::Arg(1),
            }),
        ),
        (
            "account",
            "propose",
            Accessibility::RoleGated(AuthRole::Recovery),
        ),
        (
            "account",
            "securify",
            Accessibility::Guarded(Expr::SelfAddr),
        ),
        (
            "account",
            "withdraw",
            Accessibility::Guarded(Expr::SelfAddr),
        ),
        (
            "account",
            "withdraw-nf",
            Accessibility::Guarded(Expr::SelfAddr),
        ),
        ("amm", "swap", Accessibility::Public),
        ("book", "fill-asks", Accessibility::Public),
        ("book", "place-ask", Accessibility::Public),
        ("lottery", "draw", Accessibility::Public),
        ("lottery", "enter", Accessibility::Public),
        ("splitter", "take", Accessibility::Public),
        (
            "staking",
            "cast-param-vote",
            Accessibility::Guarded(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            }),
        ),
        (
            "staking",
            "clear-param-vote",
            Accessibility::Guarded(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            }),
        ),
        (
            "staking",
            "deactivate-validator",
            Accessibility::Guarded(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            }),
        ),
        (
            "staking",
            "register-validator",
            Accessibility::Guarded(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            }),
        ),
        ("staking", "stake", Accessibility::Public),
        (
            "staking",
            "unjail",
            Accessibility::Guarded(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            }),
        ),
        ("staking", "unstake", Accessibility::Public),
    ]
}

#[test]
fn every_authored_method_declares_who_may_call_it() {
    let packages = corpus();
    let declared: Vec<_> = packages
        .iter()
        .flat_map(|(package, metadata)| {
            metadata.methods.iter().map(move |(name, signature)| {
                (*package, name.as_str(), signature.accessibility.clone())
            })
        })
        .collect();
    assert_eq!(declared, authored_accessibility());
}
