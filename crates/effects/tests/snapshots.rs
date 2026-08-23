//! What each derived package declares, committed.
//!
//! Once a package's declaration is traced from its own module, a parity
//! test against a hand-written copy compares a thing to itself. What is
//! worth guarding instead is that a change to the *derivation* shows up:
//! a lowering that started folding two clauses into one, or dropping an
//! ABI binding, would otherwise move every package at once and no test
//! would say so.
//!
//! So the snapshot is a review artifact rather than an assertion about
//! any particular value. A diff here is not a failure — it is the
//! derivation changing, which is a thing to read.
//!
//! It is rendered through [`explain`], which is the rendering the
//! command prints, so the artifact a reviewer reads and the answer an
//! author gets are one thing. That also makes this the rendering's own
//! corpus test: every clause of every package's every method passes
//! through it on the way to the file.
//!
//! It stands here, beside the other whole-corpus sweeps, because a
//! package ships with the crate holding its blob and no one of those
//! crates can see them all.
//!
//! Regenerate with `SNAPSHOT=overwrite cargo test -p hyperscale-vm-effects`.

use std::path::PathBuf;

use hyperscale_vm_effects::{PackageMetadata, explain};
use hyperscale_vm_fixtures::DECLARED as FIXTURES;
use hyperscale_vm_stdlib::DECLARED as PROTOCOL;

fn snapshot(name: &str, metadata: &PackageMetadata) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("snapshots")
        .join(format!("{name}.txt"));
    let rendered = explain(metadata);

    if std::env::var("SNAPSHOT").as_deref() == Ok("overwrite") {
        std::fs::create_dir_all(path.parent().expect("a snapshots directory"))
            .expect("create the snapshots directory");
        std::fs::write(&path, &rendered).expect("write the snapshot");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{name}: no snapshot at {} ({error}); regenerate with \
             SNAPSHOT=overwrite",
            path.display()
        )
    });
    assert_eq!(
        rendered, committed,
        "{name}: the derivation moved. Read the diff, then regenerate with \
         SNAPSHOT=overwrite if it is the change you meant"
    );
}

/// Every package either crate declares, snapshotted.
///
/// Read off the crates' own lists rather than named here, so a package
/// cannot be added and left unrendered: there is no second place to
/// remember. A missing file fails with the line that says how to write
/// it, which is the same prompt a moved declaration gets.
#[test]
fn every_declared_package_matches_its_snapshot() {
    let declared = PROTOCOL.iter().chain(FIXTURES);
    for (name, metadata) in declared {
        snapshot(name, &metadata());
    }
}
