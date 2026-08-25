//! The authored corpus, held to the rules a package is admitted under.
//!
//! Exhaustive on purpose, and an integration test on purpose: a package
//! lives with the crate that ships it, so the sweep over every package
//! has to stand where it can see them all — which is outside the crate
//! defining the rules.

use hyperscale_vm_effects::vocabulary::AUTH;
use hyperscale_vm_effects::{
    Clause, Expr, GrantedBehaviour, GrantsExpr, PACKAGE_SLOT_BASE, PackageMetadata, ResourceKind,
    RuleExpr, RuleLeaf, SlotId, SlotRef, TargetExpr, Value, check_abi, check_declarations,
};
use hyperscale_vm_fixtures::DECLARED as FIXTURES;
use hyperscale_vm_stdlib::DECLARED as PROTOCOL;
use hyperscale_vm_stdlib::staking::OWNER_BADGE;
use hyperscale_vm_types::Presence;

/// Every authored package, in the order the exhaustive sweeps read them.
///
/// Traced and hand-written alike. `nf` and `registry` are `wit_bindgen`
/// packages whose declarations are written out beside them, which makes
/// them the ones a rule the tracer happens to satisfy would miss.
///
/// Read off each crate's own list rather than named here, so a package
/// cannot be added and left unswept.
fn corpus() -> Vec<(&'static str, PackageMetadata)> {
    PROTOCOL
        .iter()
        .chain(FIXTURES)
        .map(|(name, metadata)| (*name, metadata()))
        .collect()
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
        slot: SlotRef::Fixed(AUTH),
        material: vec![],
    };
    // The rule that governs a cell, built here from the protocol's own
    // types rather than from the tracer's — so agreement is between two
    // derivations rather than one restated.
    let governs = |cell: Expr| {
        vec![RuleExpr::CountOf {
            count: 1,
            rules: vec![
                RuleExpr::Require(RuleLeaf::Stored { cell: cell.clone() }),
                RuleExpr::CountOf {
                    count: 2,
                    rules: vec![
                        RuleExpr::Require(RuleLeaf::Presence {
                            target: Box::new(TargetExpr::Point(cell)),
                            expect: Presence::Absent,
                        }),
                        RuleExpr::claim(Expr::SelfAddr),
                    ],
                },
            ],
        }]
    };
    let own_cell = |offset: u16| Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE + offset)),
        material: vec![],
    };
    let this = || vec![RuleExpr::claim(Expr::SelfAddr)];
    // The pool's operator badge grants nothing: its one instance is
    // founded where its record is written, and no `Mint` entry governs
    // a founding — so the supply is one, forever, and the address says
    // so without anyone reading the pool's methods.
    let owner_badge = || {
        vec![RuleExpr::claim(Expr::SelfResource {
            kind: ResourceKind::NonFungible,
            material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
            grants: GrantsExpr::new(),
        })]
    };
    let open = Vec::new;
    vec![
        // Where a resource lands is the holder's own choice, so setting
        // it takes the same gate spending does; retiring and being paid
        // take none, because what may happen there is the resource's
        // answer rather than this package's.
        ("account", "accept", this(), vec![]),
        (
            "account",
            "authorize",
            governs(auth_cell()),
            vec![Expr::SelfAddr],
        ),
        ("account", "burn", open(), vec![]),
        ("account", "burn-nf", open(), vec![]),
        ("account", "cancel", governs(own_cell(2)), vec![]),
        ("account", "confirm", governs(own_cell(3)), vec![]),
        ("account", "deposit", open(), vec![]),
        ("account", "deposit-nf", open(), vec![]),
        ("account", "freeze", governs(own_cell(2)), vec![]),
        (
            "account",
            "present-badge",
            governs(auth_cell()),
            vec![Expr::Arg(0)],
        ),
        (
            "account",
            "present-instance",
            governs(auth_cell()),
            vec![Expr::Tuple(vec![Expr::Arg(0), Expr::Arg(1)])],
        ),
        // Open, because it does only what the clock already licensed:
        // whoever wants a replacement enacted is whoever proposed it, and
        // it is a node in their own transaction.
        ("account", "promote", open(), vec![]),
        ("account", "propose", governs(own_cell(2)), vec![]),
        (
            "account",
            "recall",
            vec![RuleExpr::Require(RuleLeaf::Granted {
                resource: Expr::Arg(0),
                behaviour: GrantedBehaviour::Recall,
            })],
            vec![],
        ),
        ("account", "refuse", this(), vec![]),
        ("account", "securify", this(), vec![]),
        ("account", "sweep", this(), vec![]),
        ("account", "withdraw", this(), vec![]),
        ("account", "withdraw-nf", this(), vec![]),
        ("amm", "add-liquidity", open(), vec![]),
        ("amm", "instantiate", open(), vec![]),
        ("amm", "remove-liquidity", open(), vec![]),
        ("amm", "swap", open(), vec![]),
        ("amm", "trades", open(), vec![]),
        ("book", "fill-asks", open(), vec![]),
        ("book", "instantiate", open(), vec![]),
        ("book", "place-ask", open(), vec![]),
        // Every method open, and the issuer's side of the seam is bound
        // anyway: what holds `issue` is the seat's own `mint` entry,
        // injected at admission rather than declared here.
        ("capped", "instantiate", open(), vec![]),
        ("capped", "issue", open(), vec![]),
        ("capped", "retire", open(), vec![]),
        // Every method open, which is the fixture's whole point: it
        // declares nothing about who may move what it holds, and is
        // bound anyway.
        ("custodian", "deposit", open(), vec![]),
        ("custodian", "file", open(), vec![]),
        ("custodian", "instantiate", open(), vec![]),
        ("custodian", "release", open(), vec![]),
        ("custodian", "swap", open(), vec![]),
        ("custodian", "withdraw", open(), vec![]),
        ("flashloan", "draw", open(), vec![]),
        ("flashloan", "instantiate", open(), vec![]),
        ("flashloan", "repay", open(), vec![]),
        ("grammar", "accrue", open(), vec![]),
        ("grammar", "charge", open(), vec![]),
        ("grammar", "charge-or", open(), vec![]),
        ("grammar", "escrow", open(), vec![]),
        ("grammar", "file", open(), vec![]),
        ("grammar", "fund", open(), vec![]),
        ("grammar", "instantiate", open(), vec![]),
        ("grammar", "jot", open(), vec![]),
        ("grammar", "later", open(), vec![]),
        ("grammar", "ledgered", open(), vec![]),
        ("grammar", "noted", open(), vec![]),
        ("grammar", "owe-each", open(), vec![]),
        ("grammar", "raise", open(), vec![]),
        ("grammar", "reseat", open(), vec![]),
        ("grammar", "restow", open(), vec![]),
        ("grammar", "scheduled", open(), vec![]),
        ("grammar", "seat", open(), vec![]),
        ("grammar", "seated", open(), vec![]),
        ("grammar", "settle", open(), vec![]),
        ("grammar", "spread", open(), vec![]),
        ("grammar", "spread-to", open(), vec![]),
        ("grammar", "stash", open(), vec![]),
        ("grammar", "stow", open(), vec![]),
        ("grammar", "survey", open(), vec![]),
        ("grammar", "surveyed", open(), vec![]),
        ("grammar", "sweep", open(), vec![]),
        ("grammar", "take", open(), vec![]),
        ("grammar", "take-noting", open(), vec![]),
        ("grammar", "tallied", open(), vec![]),
        ("grammar", "tally", open(), vec![]),
        ("grammar", "tally-plainly", open(), vec![]),
        ("grammar", "unseat", open(), vec![]),
        ("grammar", "widest", open(), vec![]),
        ("grammar", "windowed", open(), vec![]),
        ("lending", "accrue", open(), vec![]),
        ("lending", "deposit", open(), vec![]),
        ("lending", "draw", open(), vec![]),
        ("lending", "index-scaled", open(), vec![]),
        ("lending", "instantiate", open(), vec![]),
        ("lending", "liquidate", open(), vec![]),
        (
            "lending",
            "post-price",
            vec![RuleExpr::claim(Expr::Config(2))],
            vec![],
        ),
        ("lending", "repay", open(), vec![]),
        ("lottery", "close", open(), vec![]),
        ("lottery", "enter", open(), vec![]),
        ("lottery", "instantiate", open(), vec![]),
        ("lottery", "reopen", open(), vec![]),
        ("lottery", "settle", open(), vec![]),
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
        ("payouts", "disburse", open(), vec![]),
        ("payouts", "divides", open(), vec![]),
        ("payouts", "in-lots", open(), vec![]),
        ("payouts", "instantiate", open(), vec![]),
        ("payouts", "settle", open(), vec![]),
        ("peg", "instantiate", open(), vec![]),
        (
            "peg",
            "post-deviation",
            vec![RuleExpr::claim(Expr::Config(2))],
            vec![],
        ),
        ("peg", "quote", open(), vec![]),
        ("peg", "redeem", open(), vec![]),
        (
            "perp",
            "charge-longs",
            vec![RuleExpr::claim(Expr::Config(1))],
            vec![],
        ),
        ("perp", "close", open(), vec![]),
        (
            "perp",
            "credit-longs",
            vec![RuleExpr::claim(Expr::Config(1))],
            vec![],
        ),
        ("perp", "instantiate", open(), vec![]),
        ("perp", "liquidate", open(), vec![]),
        ("perp", "open", open(), vec![]),
        (
            "perp",
            "post-mark",
            vec![RuleExpr::claim(Expr::Config(1))],
            vec![],
        ),
        ("registry", "bind", open(), vec![]),
        ("registry", "check", open(), vec![]),
        ("registry", "drain", open(), vec![]),
        // A reach declares no gate of its own: what admits it is the
        // reached resource's own entry, injected where the declaration
        // is evaluated, so this table sees an open method and the
        // resource sees the caller. Four of them here — the two halves
        // of the halt flag, and the two takings the recall entry admits.
        ("security", "freeze", open(), vec![]),
        ("security", "instantiate", open(), vec![]),
        ("security", "issue", open(), vec![]),
        ("security", "issue-bearer", open(), vec![]),
        ("security", "recall-shares", open(), vec![]),
        (
            "security",
            "register",
            vec![RuleExpr::claim(Expr::Config(0))],
            vec![],
        ),
        ("security", "release", open(), vec![]),
        ("security", "revoke", open(), vec![]),
        ("shares", "deposit", open(), vec![]),
        ("shares", "instantiate", open(), vec![]),
        ("shares", "mint", open(), vec![]),
        ("shares", "redeem", open(), vec![]),
        ("shares", "withdraw", open(), vec![]),
        ("staking", "cast-param-vote", owner_badge(), vec![]),
        ("staking", "clear-param-vote", owner_badge(), vec![]),
        ("staking", "deactivate-validator", owner_badge(), vec![]),
        (
            "staking",
            "instantiate",
            vec![RuleExpr::claim(Expr::Config(1))],
            vec![],
        ),
        ("staking", "register-validator", owner_badge(), vec![]),
        ("staking", "stake", open(), vec![]),
        ("staking", "unjail", owner_badge(), vec![]),
        ("staking", "unstake", open(), vec![]),
    ]
}

#[test]
fn every_authored_method_declares_who_may_call_it() {
    let packages = corpus();
    let mut declared: Vec<_> = packages
        .iter()
        .flat_map(|(package, metadata)| {
            metadata.methods.iter().map(move |(name, signature)| {
                let mut requires = Vec::new();
                let mut mints = Vec::new();
                for clause in signature.effects.iter().flat_map(Clause::effects) {
                    match clause {
                        Clause::Requires { rule, .. } if !rule.reads_state_only() => {
                            requires.push(rule.clone());
                        }
                        Clause::Mints { claim, .. } => mints.push(claim.clone()),
                        _ => {}
                    }
                }
                (*package, name.as_str(), requires, mints)
            })
        })
        .collect();
    // The table is written alphabetically, so the corpus reading is too:
    // which crate a package lives in is not a fact the table records.
    declared.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
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
                    reach: None,
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
