//! The authored corpus, held to the rules a package is admitted under.
//!
//! Exhaustive on purpose, and an integration test on purpose: a package
//! lives with the crate that ships it, so the sweep over every package
//! has to stand where it can see them all — which is outside the crate
//! defining the rules.

use hyperscale_vm_effects::vocabulary::AUTH;
use hyperscale_vm_effects::{
    CONFIRMATION, Clause, ConditionExpr, Expr, PRIMARY, PackageMetadata, RECOVERY, RuleExpr,
    RuleLeaf, Value, check_abi, check_declarations,
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

/// Who may call every authored method, as a table: the rules each
/// method requires, and the claims it mints.
///
/// Exhaustive on purpose. A method with no authority condition admits
/// everyone, so a method added without a thought about its callers gets
/// the permissive value silently — and the shape that is easiest to miss
/// moves no funds at all: `securify` writes a leaf under its target's
/// prefix and consumes nothing, which is the same class as any later
/// per-account module. Adding a method breaks this list, which is the
/// point.
#[allow(clippy::too_many_lines)] // one row per method, and the exhaustiveness is the point
fn authored_authority() -> Vec<(&'static str, &'static str, Vec<RuleExpr>, Vec<Expr>)> {
    let auth_cell = || Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: AUTH,
        material: vec![],
    };
    let stored = |role| {
        vec![RuleExpr::Require(RuleLeaf::Stored {
            cell: auth_cell(),
            role,
        })]
    };
    let this = || vec![RuleExpr::claim(Expr::SelfAddr)];
    let owner_badge = || {
        vec![RuleExpr::claim(Expr::SelfResource {
            material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
        })]
    };
    let open = Vec::new;
    vec![
        (
            "account",
            "authorize",
            stored(PRIMARY),
            vec![Expr::SelfAddr],
        ),
        ("account", "cancel", stored(RECOVERY), vec![]),
        ("account", "confirm", stored(CONFIRMATION), vec![]),
        ("account", "deposit", open(), vec![]),
        ("account", "deposit-nf", open(), vec![]),
        ("account", "freeze", stored(RECOVERY), vec![]),
        (
            "account",
            "present-badge",
            stored(PRIMARY),
            vec![Expr::Arg(0)],
        ),
        (
            "account",
            "present-instance",
            stored(PRIMARY),
            vec![Expr::Tuple(vec![Expr::Arg(0), Expr::Arg(1)])],
        ),
        ("account", "propose", stored(RECOVERY), vec![]),
        ("account", "securify", this(), vec![]),
        ("account", "withdraw", this(), vec![]),
        ("account", "withdraw-nf", this(), vec![]),
        ("amm", "swap", open(), vec![]),
        ("book", "fill-asks", open(), vec![]),
        ("book", "place-ask", open(), vec![]),
        ("lottery", "draw", open(), vec![]),
        ("lottery", "enter", open(), vec![]),
        ("nf", "burn", open(), vec![]),
        ("nf", "deposit", open(), vec![]),
        ("nf", "mint", open(), vec![]),
        (
            "nf",
            "operate",
            vec![RuleExpr::claim(Expr::Config(0))],
            vec![],
        ),
        (
            "nf",
            "operate-instance",
            vec![RuleExpr::claim(Expr::Tuple(vec![
                Expr::Config(0),
                Expr::Config(1),
            ]))],
            vec![],
        ),
        (
            "nf",
            "operate-quorum",
            vec![RuleExpr::CountOf {
                count: 2,
                rules: (1..=3)
                    .map(|slot| {
                        RuleExpr::claim(Expr::Tuple(vec![Expr::Config(0), Expr::Config(slot)]))
                    })
                    .collect(),
            }],
            vec![],
        ),
        ("nf", "withdraw", open(), vec![]),
        ("registry", "bind", open(), vec![]),
        ("registry", "check", open(), vec![]),
        ("registry", "drain", open(), vec![]),
        ("splitter", "take", open(), vec![]),
        ("staking", "cast-param-vote", owner_badge(), vec![]),
        ("staking", "clear-param-vote", owner_badge(), vec![]),
        ("staking", "deactivate-validator", owner_badge(), vec![]),
        ("staking", "register-validator", owner_badge(), vec![]),
        ("staking", "stake", open(), vec![]),
        ("staking", "unjail", owner_badge(), vec![]),
        ("staking", "unstake", open(), vec![]),
    ]
}

#[test]
fn every_authored_method_declares_who_may_call_it() {
    let packages = corpus();
    let declared: Vec<_> = packages
        .iter()
        .flat_map(|(package, metadata)| {
            metadata.methods.iter().map(move |(name, signature)| {
                let mut requires = Vec::new();
                let mut mints = Vec::new();
                for clause in signature.effects.iter().flat_map(Clause::effects) {
                    match clause {
                        Clause::Requires {
                            condition: ConditionExpr::Satisfies { rule },
                            ..
                        } => requires.push(rule.clone()),
                        Clause::Mints { claim, .. } => mints.push(claim.clone()),
                        _ => {}
                    }
                }
                (*package, name.as_str(), requires, mints)
            })
        })
        .collect();
    assert_eq!(declared, authored_authority());
}

/// The literal a holdings interval is declared at, held against the
/// constant it restates.
///
/// A holdings interval's cap is the count of the ids the call itself
/// names — the argument list a withdrawal takes, the edge's id
/// projection a deposit files — so an account's move declares exactly
/// the walk it performs, and a full edge always fits the interval
/// filing it by construction rather than by a constant agreeing with
/// the edge bound.
#[test]
fn the_account_files_at_the_count_it_moves() {
    use hyperscale_vm_effects::{Clause, Expr, TargetExpr};
    use hyperscale_vm_stdlib::account;

    let metadata = account::metadata();
    let declared_cap = |method: &str| {
        metadata.methods[method]
            .effects
            .iter()
            .find_map(|clause| match clause {
                Clause::Effect {
                    target: TargetExpr::Range { cap, .. },
                    ..
                } => Some(cap.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{method} declares a holdings interval"))
    };
    assert_eq!(
        declared_cap("deposit-nf"),
        Expr::Len(Box::new(Expr::IdsOf(Box::new(Expr::Arg(0))))),
        "a deposit files at the count the edge carries"
    );
    assert_eq!(
        declared_cap("withdraw-nf"),
        Expr::Len(Box::new(Expr::Arg(1))),
        "a withdrawal takes at the count the argument names"
    );
}
