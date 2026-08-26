//! What `new` writes: a package crate that builds and admits as it
//! stands.
//!
//! Five files, and each one is there because a consensus artifact is
//! reproducible or it is nothing. The manifest keeps the crate out of any
//! host workspace and fixes the codegen terms; the cargo config fixes the
//! link terms, the memory ceiling the profile requires among them; the
//! toolchain file is what makes both pins pins. The library is the
//! package, and the binary beside it prints the declaration the library
//! derives.

use std::path::{Path, PathBuf};

use crate::BuildError;

/// The manifest: a `cdylib` for the chain and an `rlib` so the
/// declaration binary can link the same library the guest build compiles.
fn manifest(name: &str, sdk: &str, testing: &str) -> String {
    format!(
        "# `trim-paths` is unstable, and the toolchain is pinned anyway.\n\
         cargo-features = [\"trim-paths\"]\n\
         \n\
         [package]\n\
         name = \"{name}\"\n\
         version = \"0.0.0\"\n\
         edition = \"2024\"\n\
         publish = false\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\", \"rlib\"]\n\
         \n\
         [dependencies]\n\
         wit-bindgen = \"=0.60.0\"\n\
         hyperscale-vm-sdk = {sdk}\n\
         \n\
         [dev-dependencies]\n\
         # The chain a test runs on: publish, seed, call, assert. It\n\
         # carries both lanes — the bodies called directly, and this\n\
         # crate built to its artifact and run under the engine a network\n\
         # would use.\n\
         hyperscale-vm-testing = {testing}\n\
         \n\
         [profile.release]\n\
         opt-level = \"s\"\n\
         lto = true\n\
         # The artifact carries no path from the machine that built it.\n\
         # Panic formatting is elided, but a `Location` survives whatever\n\
         # formats it, and the one it names is the source file's —\n\
         # absolute, and so as much a property of the checkout as the\n\
         # name section this build already strips.\n\
         trim-paths = \"all\"\n\
         # One unit per crate: nothing about the artifact's function order\n\
         # is left to codegen-unit partitioning or LTO merge order.\n\
         codegen-units = 1\n\
         \n\
         # Deliberately its own workspace: a pinned nightly and one codegen\n\
         # unit are per-workspace settings a host build must not inherit.\n\
         [workspace]\n"
    )
}

/// A module's name as the struct standing for it, which is the name
/// `#[blueprint]` holds a `#[state]` struct to.
fn pascal(module: &str) -> String {
    let mut out = String::new();
    let mut starting = true;
    for ch in module.chars() {
        if ch == '_' {
            starting = true;
        } else if starting {
            out.extend(ch.to_uppercase());
            starting = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// The package itself: one module, whose bodies are the declaration and
/// the component both.
fn library(module: &str) -> String {
    let state = pascal(module);
    format!(
        "//! A package: one module, from which the declaration routing reads\n\
         //! and the component that executes it are both derived.\n\
         \n\
         use hyperscale_vm_sdk::blueprint;\n\
         \n\
         #[blueprint]\n\
         pub mod {module} {{\n\
         \x20   use hyperscale_vm_sdk::Address;\n\
         \x20   use hyperscale_vm_sdk::state::{{Bucket, Quantity}};\n\
         \n\
         \x20   /// What this package stores of its own. The protocol's\n\
         \x20   /// cells — balances, the delivery fallback, the stored\n\
         \x20   /// authority — every owner has already.\n\
         \x20   #[state]\n\
         \x20   struct {state} {{}}\n\
         \n\
         \x20   impl {state} {{\n\
         \x20       /// Credit the vault the arriving edge belongs in.\n\
         \x20       pub fn deposit(&mut self, funds: Bucket) {{\n\
         \x20           self.vault(funds.resource()).put(funds);\n\
         \x20       }}\n\
         \n\
         \x20       /// Reserve `amount` of `resource` from this instance.\n\
         \x20       pub fn withdraw(&mut self, resource: Address, amount: Quantity) -> Bucket {{\n\
         \x20           self.vault(resource).reserve(amount)\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    )
}

/// The declaration binary: the host half of the build, whose whole job is
/// to print what `blueprint()` traced.
///
/// A binary rather than a const, because the declaration is *run* — the
/// macro emits tracer calls rather than `Expr` literals, so the tracer
/// stays the single implementation of what a declaration means.
fn declaration_bin(krate: &str, module: &str) -> String {
    format!(
        "//! Print this package's declaration as its canonical section\n\
         //! bytes. `cargo hyperscale build` runs this and attaches what it\n\
         //! prints to the code beside it.\n\
         \n\
         hyperscale_vm_sdk::declaration_main!({krate}::{module});\n"
    )
}

/// The package's first test: the loop an author works in.
///
/// Written beside the first method rather than left to be discovered,
/// because a package with no test is a package whose author's only
/// feedback is a deploy.
fn first_test(module: &str) -> String {
    let state = pascal(module);
    format!(
        "//! What this package does, against the real kernel.\n\
         \n\
         use hyperscale_vm_testing::{{Chain, account, package, principal, resource}};\n\
         use {module}::{module}::client::{state};\n\
         \n\
         // One text, and a test per engine the crate was built with: the\n\
         // bodies at the speed of a function call, and the artifact a\n\
         // network would run. Neither is wrong to run; running only one is.\n\
         #[hyperscale_vm_testing::test]\n\
         fn a_deposit_lands_in_the_vault(mut chain: Chain) {{\n\
         \x20   let alice = principal(1);\n\
         \x20   let xrd = resource(0xE1);\n\
         \n\
         \x20   chain.publish(package!({module}::{module}));\n\
         \x20   let instance = chain.instantiate::<{state}>(principal(1), ());\n\
         \x20   chain.credit(alice, xrd, 100);\n\
         \n\
         \x20   chain\n\
         \x20       .transact(alice, |b| {{\n\
         \x20           let signed_in = account::authorize(b, alice)?;\n\
         \x20           let funds = account::withdraw(b, signed_in, xrd, 40)?;\n\
         \x20           instance.deposit(b, funds)\n\
         \x20       }})\n\
         \x20       .expect_completed();\n\
         \n\
         \x20   assert_eq!(chain.balance(instance, xrd), 40);\n\
         \x20   assert_eq!(chain.balance(alice, xrd), 60);\n\
         }}\n"
    )
}

/// The link terms a package's code is built under.
///
/// Copied rather than derived, because every line is a property of the
/// artifact rather than of the crate: the profile requires a declared
/// memory maximum, the name section carries build-host salt no consensus
/// artifact should hold, and panic formatting is the only thing in a Rust
/// guest that recurses — which is what leaves the deploy-time stack bound
/// unprovable unless it is elided.
const CARGO_CONFIG: &str = "\
# Panic formatting is the only thing in a Rust guest that recurses: the
# `core::fmt` machinery calls itself, which leaves the core call graph
# cyclic and the deploy-time stack bound unprovable. `immediate-abort`
# elides it, and the profile does not bend per toolchain.
#
# It carries the abort strategy with it, which is why the release profile
# names none: `panic = \"abort\"` there would reach the crate's host builds
# too, and a test binary is compiled to unwind whatever the profile says.
[unstable]
build-std = [\"std\", \"panic_abort\"]

# The profile requires a declared memory maximum; 16 MiB = the profile's
# 256-page ceiling.
#
# `--strip-all` drops the name section: its mangled symbols embed
# crate-disambiguator hashes that cargo salts with the build host, and
# a consensus artifact carries no debug payload.
[target.wasm32-unknown-unknown]
rustflags = [
    \"-C\", \"link-arg=--max-memory=16777216\",
    \"-C\", \"link-arg=--strip-all\",
    \"-Z\", \"unstable-options\",
    \"-C\", \"panic=immediate-abort\",
]
";

/// The toolchain a package's bytes are emitted by.
///
/// `rust-src` is what `build-std` needs; the channel is pinned because
/// the artifact is a consensus input and toolchains emit the same code in
/// different function order.
const TOOLCHAIN: &str = "\
# A package's artifact is a consensus input: its bytes are what deploys,
# and the deploy-time stack bound is proven against the code this exact
# toolchain emits. Upgrades are deliberate events, never drift.
[toolchain]
channel = \"nightly-2026-06-08\"
components = [\"rust-src\"]
targets = [\"wasm32-unknown-unknown\"]
";

/// Where a scaffolded package finds the SDK.
///
/// A path while the SDK is unpublished, resolved against the new crate's
/// own location so the scaffold works from anywhere in the repository.
///
/// Here rather than in the command, because it is part of what `new`
/// writes: a manifest pointing somewhere the crate cannot build from is
/// a broken scaffold however well the rest of it reads, and a test can
/// only judge that if it can reach the same line the command emits.
///
/// The `guest` feature is what says this crate publishes the package it
/// authors, which is what a scaffolded crate is for: it earns the
/// executing component beside the declaration every consumer reads.
#[must_use]
pub fn sdk_dependency(dir: &Path) -> String {
    publisher(&crate_dependency(dir, "sdk", "\"0.1\""))
}

/// One dependency line with the publishing feature added.
fn publisher(dependency: &str) -> String {
    let features = "features = [\"guest\"]";
    dependency.strip_suffix('}').map_or_else(
        // A bare version, which has no field list to extend.
        || format!("{{ version = {dependency}, {features} }}"),
        |fields| format!("{}, {features} }}", fields.trim_end()),
    )
}

/// The test harness as a scaffolded package reaches it, on the terms
/// [`sdk_dependency`] describes.
///
/// With the blessed engine's lane, because the scaffold's own test is
/// written for both: an author who has to turn on the second engine is
/// an author whose first run proves half of what it says it does.
#[must_use]
pub fn testing_dependency(dir: &Path) -> String {
    crate_dependency(dir, "testing", "\"0.1\"")
}

/// One sibling crate as reached from `dir`, or `published` where this
/// build carries no path to it.
fn crate_dependency(dir: &Path, name: &str, published: &str) -> String {
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|crates| crates.join(name));
    sibling.map_or_else(
        || published.to_owned(),
        |path| format!("{{ path = \"{}\" }}", relative(dir, &path).display()),
    )
}

/// `sdk` as reached from `dir`, falling back to the absolute path where
/// the two share no root worth walking.
///
/// Sharing only `/` is not sharing anything: the relative form would be a
/// run of `..` as long as the path it replaces, and an absolute one at
/// least reads.
fn relative(dir: &Path, sdk: &Path) -> PathBuf {
    let Ok(from) = dir.canonicalize() else {
        return sdk.to_path_buf();
    };
    let shared = from
        .components()
        .zip(sdk.components())
        .take_while(|(a, b)| a == b)
        .count();
    if shared <= 1 {
        return sdk.to_path_buf();
    }
    let mut path = PathBuf::new();
    for _ in shared..from.components().count() {
        path.push("..");
    }
    path.extend(sdk.components().skip(shared));
    path
}

/// Write a package crate at `dir`, named for its own directory.
///
/// `sdk` is the dependency line the generated manifest points at —
/// [`sdk_dependency`] while the SDK is unpublished, a version once it is.
///
/// # Errors
///
/// [`BuildError`] if the directory already holds a crate, or if any file
/// cannot be written.
pub fn package(dir: &Path) -> Result<PathBuf, BuildError> {
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| BuildError(format!("{} is not a package name", dir.display())))?
        .to_owned();
    if dir.join("Cargo.toml").exists() {
        return Err(BuildError(format!(
            "{} already holds a crate",
            dir.display()
        )));
    }
    // The module is the package's own name, and a Rust module cannot
    // carry the hyphens a crate name may.
    let module = name.replace('-', "_");

    let write = |path: PathBuf, body: String| -> Result<(), BuildError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| BuildError(format!("create {}: {error}", parent.display())))?;
        }
        std::fs::write(&path, body)
            .map_err(|error| BuildError(format!("write {}: {error}", path.display())))
    };

    write(
        dir.join("Cargo.toml"),
        manifest(&name, &sdk_dependency(dir), &testing_dependency(dir)),
    )?;
    write(dir.join("src/lib.rs"), library(&module))?;
    write(
        dir.join(format!("src/bin/{module}-metadata.rs")),
        declaration_bin(&module, &module),
    )?;
    write(dir.join("tests/first.rs"), first_test(&module))?;
    write(dir.join(".cargo/config.toml"), CARGO_CONFIG.to_owned())?;
    write(dir.join("rust-toolchain.toml"), TOOLCHAIN.to_owned())?;
    Ok(dir.to_path_buf())
}

/// The manifest a workspace member carries: the crate alone. The
/// profile, the pins and the build configuration are the workspace's,
/// so restating any of them here is the drift the merge deleted.
fn member_manifest(name: &str) -> String {
    format!(
        "[package]\n\
         name = \"{name}\"\n\
         version = \"0.0.0\"\n\
         edition = \"2024\"\n\
         publish = false\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\", \"rlib\"]\n\
         \n\
         [dependencies]\n\
         wit-bindgen.workspace = true\n\
         hyperscale-vm-sdk.workspace = true\n\
         \n\
         [dev-dependencies]\n\
         hyperscale-vm-testing.workspace = true\n"
    )
}

/// Write a guest crate at `dir` as a member of the workspace enclosing
/// it, and add it to that workspace's members list.
///
/// The standalone shape is for an author outside this repository; a
/// member carries none of it — no `[workspace]` terminator, no profile,
/// no toolchain or cargo config of its own — because every one of those
/// is the enclosing workspace's to state once.
///
/// # Errors
///
/// [`BuildError`] if the directory already holds a crate, if the parent
/// holds no workspace manifest with a members list, or if any file
/// cannot be written.
pub fn member(dir: &Path) -> Result<PathBuf, BuildError> {
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| BuildError(format!("{} is not a package name", dir.display())))?
        .to_owned();
    if dir.join("Cargo.toml").exists() {
        return Err(BuildError(format!(
            "{} already holds a crate",
            dir.display()
        )));
    }
    let workspace = dir
        .parent()
        .map(|parent| parent.join("Cargo.toml"))
        .filter(|manifest| manifest.exists())
        .ok_or_else(|| {
            BuildError(format!(
                "{} has no enclosing workspace manifest — `--member` scaffolds into one",
                dir.display()
            ))
        })?;
    let module = name.replace('-', "_");

    let write = |path: PathBuf, body: String| -> Result<(), BuildError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| BuildError(format!("create {}: {error}", parent.display())))?;
        }
        std::fs::write(&path, body)
            .map_err(|error| BuildError(format!("write {}: {error}", path.display())))
    };

    write(dir.join("Cargo.toml"), member_manifest(&name))?;
    write(dir.join("src/lib.rs"), library(&module))?;
    write(
        dir.join(format!("src/bin/{module}-metadata.rs")),
        declaration_bin(&module, &module),
    )?;
    write(dir.join("tests/first.rs"), first_test(&module))?;
    enroll(&workspace, &name)?;
    Ok(dir.to_path_buf())
}

/// Add `name` to the members list of the workspace manifest at `path`,
/// in the sorted position the list keeps.
fn enroll(path: &Path, name: &str) -> Result<(), BuildError> {
    let manifest = std::fs::read_to_string(path)
        .map_err(|error| BuildError(format!("read {}: {error}", path.display())))?;
    let entry = format!("    \"{name}\",\n");
    if manifest.contains(entry.trim_start()) {
        return Ok(());
    }
    let open = manifest
        .find("members = [")
        .ok_or_else(|| BuildError(format!("{} declares no members list", path.display())))?;
    let list = open + "members = [".len();
    let close = manifest[list..]
        .find(']')
        .map(|at| list + at)
        .ok_or_else(|| BuildError(format!("{} members list does not close", path.display())))?;
    // The sorted position, so the list stays legible however many the
    // scaffold adds.
    let at = manifest[list..close]
        .split_inclusive('\n')
        .scan(list, |cursor, line| {
            let start = *cursor;
            *cursor += line.len();
            Some((start, line))
        })
        .find(|(_, line)| {
            let listed = line.trim().trim_matches(|c| c == '"' || c == ',');
            !listed.is_empty() && listed > name
        })
        .map_or(close, |(start, _)| start);
    let mut updated = manifest;
    updated.insert_str(at, &entry);
    std::fs::write(path, updated)
        .map_err(|error| BuildError(format!("write {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::member;

    /// The two copies that only fail in a new author's lap: the
    /// scaffold's pins against the guests workspace's own tracked
    /// files. CI and the regenerate script carry the same pin and run on
    /// every push, so a drift there fails loudly on its own; these two
    /// surface only when somebody scaffolds. The prose above each pin is
    /// its own — one speaks of a package, the other of the workspace —
    /// so what is held identical is the pin, from `[toolchain]` on.
    #[test]
    fn the_scaffolded_pins_are_the_guests_workspaces_own() {
        let pin = |text: &str| {
            let at = text.find("[toolchain]").expect("a toolchain section");
            text[at..].to_owned()
        };
        assert_eq!(
            pin(super::TOOLCHAIN),
            pin(include_str!("../../../guests/rust-toolchain.toml")),
            "the scaffold ships new authors the workspace's own toolchain"
        );
        assert_eq!(
            super::CARGO_CONFIG,
            include_str!("../../../guests/.cargo/config.toml"),
            "the scaffold ships new authors the workspace's own link terms"
        );
    }

    /// A member carries the crate alone and joins the members list in
    /// sorted position. Everything else — profile, pins, build
    /// configuration — is the workspace's to state once, and restating
    /// any of it is the drift the merge deleted seventeen copies of.
    #[test]
    fn a_member_scaffold_joins_the_workspace_and_restates_nothing() {
        let root =
            std::env::temp_dir().join(format!("hyperscale-scaffold-member-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nresolver = \"3\"\nmembers = [\n    \"aardvark\",\n    \"zebra\",\n]\n",
        )
        .unwrap();
        let dir = root.join("middling");
        std::fs::create_dir_all(&dir).unwrap();
        member(&dir).unwrap();

        let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        assert!(!manifest.contains("[workspace]"), "{manifest}");
        assert!(!manifest.contains("[profile"), "{manifest}");
        assert!(!manifest.contains("cargo-features"), "{manifest}");
        assert!(manifest.contains("hyperscale-vm-sdk.workspace = true"));
        assert!(!dir.join(".cargo/config.toml").exists());
        assert!(!dir.join("rust-toolchain.toml").exists());

        let members = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let first = members.find("aardvark").unwrap();
        let added = members.find("middling").unwrap();
        let last = members.find("zebra").unwrap();
        assert!(
            first < added && added < last,
            "sorted into place:\n{members}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
