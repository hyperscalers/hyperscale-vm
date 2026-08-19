//! The authored corpus, held to the rules a package is admitted under.
//!
//! Exhaustive on purpose, and an integration test on purpose: a package
//! lives with the crate that ships it, so the sweep over every package
//! has to stand where it can see them all — which is outside the crate
//! defining the rules.

use hyperscale_vm_effects::{
    Accessibility, AuthRole, CustodyClaim, Expr, PackageMetadata, RuleExpr, Value, check_abi,
    check_declarations,
};
use hyperscale_vm_fixtures::{amm, book, lottery, nf, registry, splitter};
use hyperscale_vm_stdlib::staking::OWNER_BADGE;
use hyperscale_vm_stdlib::{account, staking};

/// Every authored package, in the order the exhaustive sweeps read them.
///
/// Traced and hand-written alike. `nf` and `registry` are `wit_bindgen`
/// packages whose declarations are written out beside them, which makes
/// them the ones a rule the tracer happens to satisfy would miss.
fn corpus() -> Vec<(&'static str, PackageMetadata)> {
    vec![
        ("account", account::metadata()),
        ("amm", amm::metadata()),
        ("book", book::metadata()),
        ("lottery", lottery::metadata()),
        ("nf", nf::metadata()),
        ("registry", registry::metadata()),
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
#[allow(clippy::too_many_lines)] // one row per method, and the exhaustiveness is the point
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
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfAddr)),
        ),
        (
            "account",
            "withdraw",
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfAddr)),
        ),
        (
            "account",
            "withdraw-nf",
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfAddr)),
        ),
        ("amm", "swap", Accessibility::Public),
        ("book", "fill-asks", Accessibility::Public),
        ("book", "place-ask", Accessibility::Public),
        ("lottery", "draw", Accessibility::Public),
        ("lottery", "enter", Accessibility::Public),
        ("nf", "burn", Accessibility::Public),
        ("nf", "deposit", Accessibility::Public),
        ("nf", "mint", Accessibility::Public),
        (
            "nf",
            "operate",
            Accessibility::Guarded(RuleExpr::Require(Expr::Config(0))),
        ),
        (
            "nf",
            "operate-instance",
            Accessibility::Guarded(RuleExpr::Require(Expr::Tuple(vec![
                Expr::Config(0),
                Expr::Config(1),
            ]))),
        ),
        (
            "nf",
            "operate-quorum",
            Accessibility::Guarded(RuleExpr::CountOf {
                count: 2,
                rules: (1..=3)
                    .map(|slot| {
                        RuleExpr::Require(Expr::Tuple(vec![Expr::Config(0), Expr::Config(slot)]))
                    })
                    .collect(),
            }),
        ),
        ("nf", "withdraw", Accessibility::Public),
        ("registry", "bind", Accessibility::Public),
        ("registry", "check", Accessibility::Public),
        ("registry", "drain", Accessibility::Public),
        ("splitter", "take", Accessibility::Public),
        (
            "staking",
            "cast-param-vote",
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            })),
        ),
        (
            "staking",
            "clear-param-vote",
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            })),
        ),
        (
            "staking",
            "deactivate-validator",
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            })),
        ),
        (
            "staking",
            "register-validator",
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            })),
        ),
        ("staking", "stake", Accessibility::Public),
        (
            "staking",
            "unjail",
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfResource {
                material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            })),
        ),
        ("staking", "unstake", Accessibility::Public),
    ]
}

/// The literal a holdings interval is declared at, held against the
/// constant it restates.
///
/// A guest names no constant from this crate — the lowering takes an
/// entry cap as a literal, so a package writes the number — which leaves
/// the vocabulary's [`NF_MOVE_CAP`] and the account's `64` two copies of
/// one bound with nothing between them. This is what is between them.
#[test]
fn the_account_files_at_the_cap_the_vocabulary_names() {
    use hyperscale_vm_effects::vocabulary::NF_MOVE_CAP;
    use hyperscale_vm_effects::{Clause, TargetExpr};
    use hyperscale_vm_stdlib::account;

    let metadata = account::metadata();
    for method in ["deposit-nf", "withdraw-nf"] {
        let declared = metadata.methods[method]
            .effects
            .iter()
            .find_map(|clause| match clause {
                Clause::Effect {
                    target: TargetExpr::Range { cap, .. },
                    ..
                } => Some(*cap),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{method} declares a holdings interval"));
        assert_eq!(
            declared, NF_MOVE_CAP,
            "{method} files at {declared} where the vocabulary names {NF_MOVE_CAP}"
        );
    }
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
