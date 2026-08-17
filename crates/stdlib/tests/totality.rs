//! Every genesis method's totality mark, judged against the blob that
//! carries it.
//!
//! The metadata in this crate is hand-authored and the artifacts beside it
//! are committed bytes, so nothing but a test holds the two together. What
//! makes that worth a file of its own is which way the claim points: a
//! method marked total is one a core commits against without waiting to
//! hear back, so a mark the code cannot support is a torn settlement
//! rather than a lost optimisation.

use hyperscale_vm_effects::Accessibility;
use hyperscale_vm_runtime::check_method;
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, STAKING_COMPONENT, account, staking};

/// One method, as the two conditions below see it.
struct Method {
    name: String,
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
        ("account", ACCOUNT_COMPONENT, account::metadata()),
        ("staking", STAKING_COMPONENT, staking::metadata()),
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
                open: signature.accessibility == Accessibility::Public,
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
/// `stake` sits outside it and `unstake` does not, which is the whole of
/// what a derived body costs: an export returning a value builds its
/// `list<u8>` on the heap, and allocation failure is a fault the scan is
/// right to see. A method that only moves amounts reaches no allocator,
/// so what separates the two is the result shape rather than the body.
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
        vec![
            "account::deposit".to_string(),
            // The pool's own delegation earns the mark once its body is
            // a transfer: what it hands back is a handle, so nothing on
            // its path reaches the allocator.
            "staking::stake".to_string(),
            "staking::unstake".to_string(),
        ],
        "the methods eligible for the mark moved; decide whether the marks should follow",
    );
}
