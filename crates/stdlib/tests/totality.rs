//! Every genesis method's totality mark, judged against the blob that
//! carries it.
//!
//! The metadata in this crate is hand-authored and the artifacts beside it
//! are committed bytes, so nothing but a test holds the two together. What
//! makes that worth a file of its own is which way the claim points: a
//! method marked total is one a core commits against without waiting to
//! hear back, so a mark the code cannot support is a torn settlement
//! rather than a lost optimisation.

use hyperscale_hbor::Name;
use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{Clause, Expr, ModeExpr, ParamType, SlotRef, TargetExpr};
use hyperscale_vm_runtime::check_method;
use hyperscale_vm_stdlib::{ACCOUNT_MODULE, STAKING_MODULE, account, staking};
use hyperscale_vm_types::Moves;

/// One method, as the two conditions below see it.
struct Method {
    name: Name,
    /// Whether its metadata claims the mark.
    marked: bool,
    /// Whether its door is open to everyone — a gated method carries a
    /// refusal the artifact scan cannot see.
    open: bool,
}

/// One genesis package: the metadata's claims beside the bytes that
/// either support them or do not.
struct Package {
    name: &'static str,
    artifact: &'static [u8],
    methods: Vec<Method>,
}

fn packages() -> Vec<Package> {
    [
        ("account", ACCOUNT_MODULE, account::metadata()),
        ("staking", STAKING_MODULE, staking::metadata()),
    ]
    .into_iter()
    .map(|(name, artifact, metadata)| Package {
        name,
        artifact,
        methods: metadata
            .methods
            .iter()
            .map(|(name, signature)| Method {
                name: name.clone(),
                marked: signature.totality.is_total(),
                open: !signature.requires_evidence(),
            })
            .collect(),
    })
    .collect()
}

/// Nothing claims totality that its own code cannot support.
///
/// The direction that matters, and the one asserted unconditionally: a
/// mark the artifact refuses is a promise the protocol would be making on
/// behalf of code that can break it.
#[test]
fn every_marked_method_survives_its_artifact() {
    for package in packages() {
        for method in package.methods {
            if !method.marked {
                continue;
            }
            let (name, artifact) = (package.name, package.artifact);
            assert_eq!(
                check_method(artifact, &method.name),
                Ok(()),
                "{name}::{} is marked total and its artifact says otherwise",
                method.name,
            );
        }
    }
}

/// Which methods could carry the mark, pinned.
///
/// A candidate is one whose body the scan admits *and* whose door is open
/// to everyone. Both are necessary and neither is sufficient: the scan
/// speaks only to trapping, and a gate is a refusal the body never runs
/// to reach — which is why the second half is a metadata rule rather than
/// something the artifact could answer.
///
/// Pinned rather than asserted-as-marked, because what remains after both
/// is a judgement. Fixing the set means a guest rebuild that changes it
/// has to be looked at rather than absorbed.
///
/// The set is one method, and each near miss names the refusal that
/// keeps it out. `deposit-nf` files into a capped interval, and a
/// holdings collection near its declared cap refuses the write. `stake`
/// mints and `unstake` burns, and a supply movement is judged against
/// the accumulator's bounds at the call. Each is a refusal the caller
/// can actually meet, so the scan is right to see it — a mark on any of
/// these would be a promise the body cannot keep.
#[test]
fn the_candidates_for_the_mark_are_what_they_were() {
    let mut candidates: Vec<String> = Vec::new();
    for package in packages() {
        for method in package.methods {
            // A method the artifact does not export is a different
            // defect, and the publish gate already catches it.
            if method.open && check_method(package.artifact, &method.name) == Ok(()) {
                candidates.push(format!("{}::{}", package.name, method.name));
            }
        }
    }
    candidates.sort();

    assert_eq!(
        candidates,
        vec!["account::deposit".to_string()],
        "the methods eligible for the mark moved; decide whether the marks should follow",
    );
}

/// Every method carrying the mark takes one fungible bucket and
/// declares one effect: a credit of that bucket to its own target's
/// vault for the bucket's resource.
///
/// What an owed crossing's consumer fold stands on. The fold credits the
/// consumer's vault from the record and runs no body, which is the
/// method's whole effect only while every total method is this deposit.
/// A second total method of any other shape has to fail here, or bring
/// its own movement to the fold.
#[test]
fn a_total_method_is_a_vault_deposit() {
    let bucket = || Expr::ResourceOf(Box::new(Expr::Arg(0)));
    let deposit = vec![Clause::Effect {
        guard: None,
        target: TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotRef::Fixed(VAULT),
            material: vec![bucket()],
        }),
        mode: ModeExpr::Delta { moves: Moves::In },
        denomination: Some(Box::new(bucket())),
        reach: None,
    }];
    for (name, metadata) in [
        ("account", account::metadata()),
        ("staking", staking::metadata()),
    ] {
        for (method, signature) in &metadata.methods {
            if !signature.totality.is_total() {
                continue;
            }
            assert_eq!(
                signature.params,
                [ParamType::Bucket],
                "{name}::{method} is total and takes something other than one fungible bucket",
            );
            assert_eq!(
                signature.effects, deposit,
                "{name}::{method} is total and declares something other than its vault's credit",
            );
            assert!(
                signature.issues.is_empty() && signature.destroys.is_empty(),
                "{name}::{method} is total and moves supply",
            );
        }
    }
}
