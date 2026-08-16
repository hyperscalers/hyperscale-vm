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
fn manifest(name: &str, sdk: &str) -> String {
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
         wit-bindgen = \"=0.60.0\"\n\
         hyperscale-vm-sdk = {sdk}\n\
         \n\
         [profile.release]\n\
         opt-level = \"s\"\n\
         lto = true\n\
         # One unit per crate: nothing about the artifact's function order\n\
         # is left to codegen-unit partitioning or LTO merge order.\n\
         codegen-units = 1\n\
         panic = \"abort\"\n\
         \n\
         # Deliberately its own workspace: a pinned nightly, `panic = \"abort\"`\n\
         # and one codegen unit are per-workspace settings a host build must\n\
         # not inherit.\n\
         [workspace]\n"
    )
}

/// The package itself: one module, whose bodies are the declaration and
/// the component both.
fn library(module: &str) -> String {
    format!(
        "//! A package: one module, from which the declaration routing reads\n\
         //! and the component that executes it are both derived.\n\
         \n\
         use hyperscale_vm_sdk::blueprint;\n\
         \n\
         #[blueprint]\n\
         pub mod {module} {{\n\
         \x20   use hyperscale_vm_sdk::Address;\n\
         \x20   use hyperscale_vm_sdk::state::{{Amount, Bucket, Keyed}};\n\
         \n\
         \x20   #[state]\n\
         \x20   struct State {{\n\
         \x20       #[role(1)]\n\
         \x20       vaults: Keyed<Amount>,\n\
         \x20   }}\n\
         \n\
         \x20   impl State {{\n\
         \x20       /// Credit the vault the arriving edge belongs in.\n\
         \x20       pub fn deposit(&mut self, funds: Bucket) {{\n\
         \x20           self.vaults.at(funds.resource()).add(funds.amount());\n\
         \x20       }}\n\
         \n\
         \x20       /// Reserve `amount` of `resource` from this instance.\n\
         \x20       pub fn withdraw(&mut self, resource: Address, amount: u128) -> Bucket {{\n\
         \x20           self.vaults.at(resource).reserve(amount)\n\
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
         use std::io::Write as _;\n\
         \n\
         fn main() {{\n\
         \x20   let metadata = {krate}::{module}::blueprint().metadata();\n\
         \x20   let bytes = hyperscale_vm_sdk::encode_metadata(&metadata)\n\
         \x20       .expect(\"a traced declaration encodes\");\n\
         \x20   std::io::stdout()\n\
         \x20       .write_all(&bytes)\n\
         \x20       .expect(\"write the declaration\");\n\
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

/// Write a package crate at `dir`, named for its own directory.
///
/// `sdk` is the dependency line the generated manifest points at — a path
/// inside this repository, a version once the SDK is published.
///
/// # Errors
///
/// [`BuildError`] if the directory already holds a crate, or if any file
/// cannot be written.
pub fn package(dir: &Path, sdk: &str) -> Result<PathBuf, BuildError> {
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

    write(dir.join("Cargo.toml"), manifest(&name, sdk))?;
    write(dir.join("src/lib.rs"), library(&module))?;
    write(
        dir.join("src/bin/metadata.rs"),
        declaration_bin(&module, &module),
    )?;
    write(dir.join(".cargo/config.toml"), CARGO_CONFIG.to_owned())?;
    write(dir.join("rust-toolchain.toml"), TOOLCHAIN.to_owned())?;
    Ok(dir.to_path_buf())
}
