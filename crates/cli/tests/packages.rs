//! The command against real packages: a `#[blueprint]` module, built to
//! an artifact, judged by the gate the chain runs.
//!
//! What this closes is the one thing the derivation could not check about
//! itself. `macro_parity` compares derived metadata against a hand-written
//! fixture, which says the two agree; it cannot say the metadata agrees
//! with the *component* — that is the publish gate's question, and the
//! generator now answers to it. `check_abi_against_export` and the
//! totality biconditional stop judging hand-authoring here and start
//! judging our own emission, so a disagreement is the generator's bug.

use std::path::PathBuf;

use hyperscale_vm_cli::{artifact, declaration};
use hyperscale_vm_gate::extract_metadata;

/// The packages authored as one module apiece: the corpus's own, the
/// account's derived twin while its own guest is still hand-written, and
/// one whose whole content is the shapes the grammar admits.
const PACKAGES: &[&str] = &["amm", "book", "derived-account", "grammar"];

fn guests() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates| crates.parent())
        .expect("crates/cli sits two below the root")
        .join("guests")
}

/// Every derived package builds to a component the gate admits against
/// the declaration the same module produced.
///
/// No hand-written WIT and no hand-written `AbiParam` anywhere in the
/// three: the world is synthesised from the bodies, the binding is the
/// export's own parameter list, and the gate compares them.
#[test]
fn a_derived_package_admits_against_its_own_declaration() {
    for package in PACKAGES {
        let dir = guests().join(package);
        artifact(&dir).unwrap_or_else(|error| panic!("{package}: {error}"));
    }
}

/// The declaration a package publishes is the one its module traced.
///
/// The artifact carries the metadata, so reading it back is reading what
/// a consumer would: an encode that dropped a field would publish a
/// weaker package than the author wrote, and nothing downstream would
/// notice.
#[test]
fn a_built_artifact_carries_the_declaration_its_module_derived() {
    for package in PACKAGES {
        let dir = guests().join(package);
        let traced = declaration(&dir).unwrap_or_else(|error| panic!("{package}: {error}"));
        let built = artifact(&dir).unwrap_or_else(|error| panic!("{package}: {error}"));
        let carried = extract_metadata(&built)
            .unwrap_or_else(|error| panic!("{package}: {error}"))
            .unwrap_or_else(|| panic!("{package}: the artifact declares nothing"));
        assert_eq!(carried, traced, "{package}: the artifact's declaration");
    }
}
