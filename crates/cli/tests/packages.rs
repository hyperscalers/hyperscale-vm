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

use std::collections::BTreeMap;
use std::path::PathBuf;

use hyperscale_vm_cli::{
    Address, AddressClass, GateError, Provenance, artifact, declaration, explain,
    explain_gate_refusal, explain_issued, explain_method, scaffold,
};
use hyperscale_vm_fixtures::security;
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

/// Every package crate in `guests/` that authors a `#[blueprint]`.
fn blueprint_crates() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(guests())
        .expect("the guests directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|dir| dir.join("Cargo.toml").exists())
        .filter(|dir| {
            std::fs::read_to_string(dir.join("src").join("lib.rs"))
                .is_ok_and(|source| source.contains("#[blueprint"))
        })
        .collect();
    found.sort();
    found
}

/// Every package crate derives its own declaration through the command
/// an author would use.
///
/// The derivation snapshots are taken host-side through a `#[path]`
/// include, which reaches a module whether or not the crate holding it
/// can be built as a package at all. So a crate shipping no declaration
/// binary has its declaration swept in full and is still unbuildable by
/// the one command an author has — which is how three of them shipped.
#[test]
fn every_package_crate_derives_its_declaration_through_the_command() {
    let crates = blueprint_crates();
    assert!(crates.len() > 10, "the corpus is the sweep's whole subject");
    for dir in crates {
        declaration(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    }
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

/// A package explains itself in the names its author wrote.
///
/// The command's own path end to end: the host build produces the
/// declaration, and the rendering resolves it through the tables that
/// same declaration carries. What it proves beyond the rendering's own
/// corpus test is the wiring — that `explain` is reading a real
/// package's metadata rather than something assembled for it.
#[test]
fn a_package_explains_itself_in_the_names_its_author_wrote() {
    let dir = guests().join("lottery");
    let metadata = declaration(&dir).unwrap_or_else(|error| panic!("lottery: {error}"));

    let entered = explain_method(&metadata, "enter").expect("the lottery declares `enter`");
    assert!(
        entered.contains("self.tickets"),
        "the slot is named, not numbered:\n{entered}"
    );
    assert!(
        explain_method(&metadata, "no-such-method").is_none(),
        "a method the package does not declare explains as nothing"
    );

    // The whole package carries what one method cannot: the tables the
    // names come out of.
    let whole = explain(&metadata);
    assert!(
        whole.contains("round-truncated"),
        "the error table:\n{whole}"
    );
}

/// Who the register names, as an author would write it on the line.
const fn principal_text() -> Address {
    Address::new([0xC1; 31], AddressClass::Principal)
}

/// What a package's resources say to a holder, at the addresses a network
/// would derive.
///
/// The rendering is a holder's, so a wrong address in it is worse than no
/// rendering — which is why this goes through the protocol hash rather
/// than a test one, and why a rule reading configuration the command
/// cannot know is refused by name instead of sealed against a stand-in.
#[test]
fn a_package_says_what_its_resources_say_to_a_holder() {
    // The share class, whose every rule reads `config.registrar` — the
    // shape this command exists for, and the one a declaration cannot
    // answer alone. Read from the fixture rather than built, because it
    // carries no metadata binary of its own yet.
    let metadata = security::metadata();
    let registrar = principal_text();

    // Every rule of this issuer reads `config.registrar`, so asking
    // without it is refused, and the refusal names the flag.
    let refused = explain_issued(&metadata, None, &BTreeMap::new())
        .expect_err("the share class reads configuration");
    assert!(
        refused.to_string().contains("--config registrar=<address>"),
        "{refused}"
    );

    let config = BTreeMap::from([("registrar".to_owned(), registrar)]);
    let told = explain_issued(&metadata, None, &config).expect("the rules seal");
    // The stand-in is declared rather than left for the reader to find.
    assert!(told.contains("stand-in"), "{told}");
    // And the holder-facing reading is there: the register entry that
    // cannot leave the holder it was issued to.
    assert!(told.contains("withdraw"), "{told}");
    // The protocol hash and no other. A resource's address is the hash of
    // its record, so this rendering on a different hasher would name a
    // resource no network has — which is the one thing a holder cannot
    // be handed.
    assert!(
        told.contains(
            "restricted:3ad1723eaaf3149c012bfffd1d2d3c166268e91ab3a579acb4785461884a5006"
        ),
        "the address blake3 derives:\n{told}"
    );
    assert!(
        told.contains("nobody, ever"),
        "the soulbound entry:\n{told}"
    );

    // The addresses are the ones a network derives, not a test hash's:
    // the same record, hashed the same way, is the same address.
    let instance = Address::new([0x33; 31], AddressClass::Component);
    let named = explain_issued(&metadata, Some(instance), &config).expect("the rules seal");
    assert!(!named.contains("stand-in"), "a named instance stands alone");
    assert_ne!(
        named, told,
        "a different issuer derives different addresses"
    );
}

/// A gate refusal names a clause by index, and the build prints the
/// declaration that index is into.
///
/// The sentence on its own sends an author counting clauses. Beneath the
/// listing it names a line. Which method the gate refused is the gate's
/// own answer now rather than a phrase inside the message, so this is a
/// lookup rather than a parse.
#[test]
fn a_gate_refusal_carries_the_declaration_its_indices_are_into() {
    let dir = guests().join("lottery");
    let metadata = declaration(&dir).unwrap_or_else(|error| panic!("lottery: {error}"));

    let about_a_method =
        GateError::new("ABI parameter 2 borrows site 1 of clause 0").about("enter");
    let told = explain_gate_refusal(&about_a_method, &metadata);
    assert!(told.contains("ABI parameter 2"), "the sentence:\n{told}");
    assert!(told.contains("self.tickets"), "and the listing:\n{told}");

    // A refusal about the package has no method to look up, and reads as
    // its own sentence.
    let about_the_package = GateError::new("the package declares no way to make a component");
    assert_eq!(
        explain_gate_refusal(&about_the_package, &metadata),
        about_the_package.to_string(),
    );

    // Nor does a method the package does not declare invent a listing.
    let elsewhere = GateError::new("something").about("no-such-method");
    assert_eq!(
        explain_gate_refusal(&elsewhere, &metadata),
        elsewhere.to_string(),
    );
}

/// A manifest naming no `#[blueprint]` module is refused with the exact
/// TOML to add, before anything builds.
#[test]
fn a_manifest_without_the_module_key_names_the_key_to_add() {
    let dir = std::env::temp_dir().join(format!("hyperscale-keyless-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch dir writes");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"keyless-guest\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )
    .expect("a manifest writes");
    std::fs::write(dir.join("src").join("lib.rs"), "").expect("a library writes");

    let refused = declaration(&dir).expect_err("a manifest naming no module");
    assert!(
        refused
            .to_string()
            .contains("[package.metadata.hyperscale]"),
        "the refusal spells the table: {refused}"
    );
    assert!(
        refused
            .to_string()
            .contains("module = \"keyless_guest::<module>\""),
        "and the key, on the crate's own name: {refused}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The publish intent round-trips the codec carrying exactly the bytes
/// the gate admitted, unsigned and naming its payer and network.
#[test]
fn the_publish_envelope_carries_the_admitted_artifact() {
    use hyperscale_hbor::from_slice as decode;
    use hyperscale_vm_cli::{NetworkId, PrincipalAddr, publish_envelope};
    use hyperscale_vm_gate::admit_package;
    use hyperscale_vm_types::{SchemeId, TransactionBody, TransactionEnvelope};

    let dir = guests().join("flashloan");
    let bytes = artifact(&dir, Provenance::Published).expect("flashloan builds");
    let payer = PrincipalAddr::new([0x41; 31]);
    let intent = publish_envelope(bytes.clone(), payer, NetworkId(7)).expect("the intent encodes");

    let decoded: TransactionEnvelope = decode(&intent).expect("the intent round-trips");
    assert_eq!(decoded.network, NetworkId(7));
    assert_eq!(decoded.fee_payer, payer);
    assert_eq!(decoded.signer_scheme, SchemeId::NONE, "unsigned");
    let TransactionBody::Publish(carried) = decoded.body else {
        panic!("a publish body");
    };
    assert_eq!(carried, bytes, "exactly the artifact the gate admitted");
    admit_package(&carried).expect("the same gate admits the carried bytes");
}
