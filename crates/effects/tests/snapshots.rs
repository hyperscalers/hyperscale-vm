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
use hyperscale_vm_fixtures::{
    amm, book, grammar, lending, lottery, nf, payouts, peg, perp, registry, shares,
};
use hyperscale_vm_stdlib::{account, staking};

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

#[test]
fn the_account_declares_what_its_snapshot_records() {
    snapshot("account", &account::metadata());
}

#[test]
fn the_pool_declares_what_its_snapshot_records() {
    snapshot("amm", &amm::metadata());
}

#[test]
fn the_book_declares_what_its_snapshot_records() {
    snapshot("book", &book::metadata());
}

#[test]
fn the_lottery_declares_what_its_snapshot_records() {
    snapshot("lottery", &lottery::metadata());
}

#[test]
fn the_stake_pool_declares_what_its_snapshot_records() {
    snapshot("staking", &staking::metadata());
}

#[test]
fn the_share_vault_declares_what_its_snapshot_records() {
    snapshot("shares", &shares::metadata());
}

#[test]
fn the_splitter_declares_what_its_snapshot_records() {
    snapshot("payouts", &payouts::metadata());
}

#[test]
fn the_lending_market_declares_what_its_snapshot_records() {
    snapshot("lending", &lending::metadata());
}

#[test]
fn the_redemption_window_declares_what_its_snapshot_records() {
    snapshot("peg", &peg::metadata());
}

#[test]
fn the_perpetual_declares_what_its_snapshot_records() {
    snapshot("perp", &perp::metadata());
}

/// The shape corpus, which is the one package whose whole purpose is to
/// hold every form the grammar admits — so its snapshot is the widest
/// reading of the derivation there is.
#[test]
fn the_grammar_declares_what_its_snapshot_records() {
    snapshot("grammar", &grammar::metadata());
}

/// The two hand-authored packages.
///
/// Nothing derives these, so a diff here is not the derivation moving —
/// it is somebody editing the declaration, which is the other thing a
/// reader wants to catch. They are here because a hand-written signature
/// drifting from the guest it describes is exactly what the corpus
/// sweeps exist for, and a rendering is how a person checks it.
#[test]
fn the_hand_authored_packages_declare_what_their_snapshots_record() {
    snapshot("nf", &nf::metadata());
    snapshot("registry", &registry::metadata());
}
