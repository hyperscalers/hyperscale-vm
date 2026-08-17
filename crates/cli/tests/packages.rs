//! The command against real packages: a `#[blueprint]` module, built to
//! an artifact, judged by the gate the chain runs.
//!
//! What this closes is the one thing a snapshot of the derivation cannot:
//! a committed declaration says what the module traced, and says nothing
//! about whether the *component* beside it will take those arguments.
//! That is the publish gate's question, and the generator answers to it
//! here. `check_abi_against_export` and the
//! totality biconditional stop judging hand-authoring here and start
//! judging our own emission, so a disagreement is the generator's bug.

use std::path::PathBuf;

use hyperscale_vm_cli::{Provenance, artifact, declaration, scaffold};
use hyperscale_vm_gate::extract_metadata;

/// The packages authored as one module apiece: the corpus's own, and one
/// whose whole content is the shapes the grammar admits.
///
/// Each carries the provenance it is really built under. The two the
/// protocol seeds go through the gate that reads a totality claim against
/// the code; everything else through the one that refuses the claim
/// outright, which is what a publisher would meet.
const PACKAGES: &[(&str, Provenance)] = &[
    ("account", Provenance::Protocol),
    ("staking", Provenance::Protocol),
    ("amm", Provenance::Published),
    ("book", Provenance::Published),
    ("lottery", Provenance::Published),
    ("grammar", Provenance::Published),
    ("shares", Provenance::Published),
];

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
/// No hand-written WIT and no hand-written `AbiParam` anywhere in them:
/// the world is synthesised from the bodies, the binding is the export's
/// own parameter list, and the gate compares them.
#[test]
fn a_derived_package_admits_against_its_own_declaration() {
    for (package, provenance) in PACKAGES {
        let dir = guests().join(package);
        artifact(&dir, *provenance).unwrap_or_else(|error| panic!("{package}: {error}"));
    }
}

/// What `new` writes builds and admits as it stands.
///
/// The scaffold is a package crate like any other, and the only one
/// nobody maintains: the corpus is edited when the vocabulary moves and
/// the template is not, so a rename reaches it last and an author meets
/// the result on their first command. Judged through the same call the
/// command makes — the dependency line included, which is why that line
/// is the library's and not the binary's.
#[test]
fn the_scaffold_builds_and_admits_as_it_stands() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("scaffold");
    // The template's own files, and nothing else: a `target` left from a
    // previous run is what keeps this from rebuilding the SDK each time.
    for stale in [
        "Cargo.toml",
        "src",
        "tests",
        ".cargo",
        "rust-toolchain.toml",
    ] {
        let path = dir.join(stale);
        let _ = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
    std::fs::create_dir_all(&dir).expect("the scaffold directory");

    scaffold::package(&dir).expect("the scaffold writes");
    artifact(&dir, Provenance::Published)
        .unwrap_or_else(|error| panic!("the scaffolded package must admit: {error}"));

    // And the test it ships with passes. An author's first command is
    // `new` and the second is `cargo test`, so a template whose test did
    // not compile would be the first thing anyone met.
    let ran = std::process::Command::new("cargo")
        .args(["test", "--quiet"])
        .current_dir(&dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("CARGO_HOME")
        .env_remove("RUSTC")
        .env_remove("RUSTUP_HOME")
        .output()
        .expect("cargo runs in the scaffold");
    let stdout = String::from_utf8_lossy(&ran.stdout);
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(
        ran.status.success(),
        "the scaffolded package's own test must pass:\n{stdout}\n{stderr}",
    );
    // Silently, too. A warning here is one the template wrote, on a line
    // its author did not — and the exit status says nothing about it.
    assert!(
        !stderr.contains("warning:"),
        "the scaffolded package must compile clean:\n{stderr}",
    );
}

/// The declaration a package publishes is the one its module traced.
///
/// The artifact carries the metadata, so reading it back is reading what
/// a consumer would: an encode that dropped a field would publish a
/// weaker package than the author wrote, and nothing downstream would
/// notice.
#[test]
fn a_built_artifact_carries_the_declaration_its_module_derived() {
    for (package, provenance) in PACKAGES {
        let dir = guests().join(package);
        let traced = declaration(&dir).unwrap_or_else(|error| panic!("{package}: {error}"));
        let built =
            artifact(&dir, *provenance).unwrap_or_else(|error| panic!("{package}: {error}"));
        let carried = extract_metadata(&built)
            .unwrap_or_else(|error| panic!("{package}: {error}"))
            .unwrap_or_else(|| panic!("{package}: the artifact declares nothing"));
        assert_eq!(carried, traced, "{package}: the artifact's declaration");
    }
}
