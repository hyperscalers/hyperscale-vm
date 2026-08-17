//! Building a package crate into an artifact the chain admits.
//!
//! A package is one module, and this is the command that turns it into
//! bytes: the code from a `wasm32` build of the crate's library, the
//! declaration from a host build of the same crate, and the artifact from
//! attaching one to the other. Then [`hyperscale_vm_gate::admit_package`],
//! run against exactly the bytes a publish would carry — so a package
//! that builds here has passed the call admission runs, rather than a
//! reimplementation of it that agrees until it does not.
//!
//! # Two builds of one crate
//!
//! The metadata is produced by *running* `blueprint()`, not by
//! const-evaluating it: `#[blueprint]` deliberately emits tracer calls
//! rather than `Expr` literals, so the tracer stays the single
//! implementation of what a declaration means. That needs a host binary,
//! and the code needs a `wasm32` library, and one `cargo` invocation
//! cannot be both.
//!
//! Package crates therefore stay outside any host workspace, for the
//! reason they already do: a pinned nightly, `panic = "abort"` and one
//! codegen unit are per-workspace settings a host build must not inherit.

use std::path::{Path, PathBuf};
use std::process::Command;

use hyperscale_vm_effects::PackageMetadata;
pub use hyperscale_vm_gate::Provenance;
use hyperscale_vm_gate::{admit_package, admit_protocol_package, attach_metadata, decode_metadata};
use hyperscale_vm_runtime::validate_component;
use wit_component::ComponentEncoder;

pub mod scaffold;

/// Why a package could not be built.
///
/// One error carrying its own sentence, on the same terms as
/// [`hyperscale_vm_gate::GateError`]: what a caller needs is what to
/// print, and every refusal here is already phrased for whoever is
/// reading the terminal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct BuildError(pub String);

impl BuildError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// The wasm32 target every package's code is built for.
const TARGET: &str = "wasm32-unknown-unknown";

/// Run `cargo` in `dir` with the caller's toolchain selection scrubbed.
///
/// A `cargo` spawned from inside a cargo run inherits `RUSTUP_TOOLCHAIN`,
/// which overrides the package's own `rust-toolchain.toml` and would build
/// a consensus artifact with whatever the host happens to have. The pin is
/// only a pin if it wins.
fn cargo(dir: &Path, args: &[&str]) -> Result<std::process::Output, BuildError> {
    Command::new("cargo")
        .args(args)
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("CARGO_HOME")
        .env_remove("RUSTC")
        .env_remove("RUSTUP_HOME")
        .output()
        .map_err(|error| BuildError::new(format!("spawn cargo in {}: {error}", dir.display())))
}

/// The single wasm the crate's library build produced.
///
/// Found rather than named: a package's artifact is whatever its own
/// `[package] name` compiles to, and a lookup by convention would refuse
/// a crate for being called something else. More than one is the one case
/// worth refusing, because picking would be picking arbitrarily.
fn built_wasm(dir: &Path) -> Result<PathBuf, BuildError> {
    let out = dir.join("target").join(TARGET).join("release");
    let entries = std::fs::read_dir(&out)
        .map_err(|error| BuildError::new(format!("read {}: {error}", out.display())))?;
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "wasm")
        })
        .collect();
    found.sort();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(BuildError::new(format!(
            "no wasm in {} — the crate builds no cdylib",
            out.display()
        ))),
        _ => Err(BuildError::new(format!(
            "{} wasm files in {}; a stale one from a renamed crate is the usual cause",
            found.len(),
            out.display()
        ))),
    }
}

/// The package's code: its library built for wasm32 and componentized.
///
/// The bare component, before any metadata is attached — which is what a
/// consumer holding only code wants, and what the committed blobs are.
///
/// # Errors
///
/// [`BuildError`] if the guest build, the componentization, or the
/// deterministic profile refuses.
pub fn compile(dir: &Path) -> Result<Vec<u8>, BuildError> {
    // `--lib` alone: the metadata binary beside it is a host program, and
    // asking wasm32 to build one would ask for a `main` that is
    // deliberately not there.
    let built = cargo(dir, &["build", "--release", "--lib", "--target", TARGET])?;
    if !built.status.success() {
        return Err(BuildError::new(format!(
            "the package's code did not build:\n{}",
            String::from_utf8_lossy(&built.stderr)
        )));
    }
    let core = std::fs::read(built_wasm(dir)?)
        .map_err(|error| BuildError::new(format!("read the core module: {error}")))?;
    // wit-component's API errors with `anyhow::Error`, which has no
    // `StdError` impl to convert through; flatten its chain instead.
    let component = ComponentEncoder::default()
        .validate(true)
        .module(&core)
        .map_err(|error| BuildError::new(format!("encode component: {error:#}")))?
        .encode()
        .map_err(|error| BuildError::new(format!("componentize: {error:#}")))?;
    validate_component(&component).map_err(|error| {
        BuildError::new(format!("the component is outside the profile: {error}"))
    })?;
    Ok(component)
}

/// The package's declaration, from a host build of the same crate.
///
/// Runs the crate's `metadata` binary, whose whole job is to print the
/// canonical section bytes of `blueprint()`. Its output is decoded here
/// rather than trusted as text, so a binary that printed anything else
/// fails now instead of at attach time.
///
/// # Errors
///
/// [`BuildError`] if the host build fails, the binary does not run, or
/// what it printed is not canonical metadata.
pub fn declaration(dir: &Path) -> Result<PackageMetadata, BuildError> {
    let run = cargo(dir, &["run", "--release", "--quiet", "--bin", "metadata"])?;
    if !run.status.success() {
        return Err(BuildError::new(format!(
            "the package's declaration did not build:\n{}",
            String::from_utf8_lossy(&run.stderr)
        )));
    }
    decode_metadata(&run.stdout)
        .map_err(|error| BuildError::new(format!("the declaration is not canonical: {error}")))
}

/// The publishable artifact: the code, the declaration attached to it,
/// and the publish gate's verdict on the result.
///
/// # Errors
///
/// [`BuildError`] from either build, or carrying the gate's own sentence
/// when the artifact is one the chain would refuse.
pub fn artifact(dir: &Path, provenance: Provenance) -> Result<Vec<u8>, BuildError> {
    let component = compile(dir)?;
    let metadata = declaration(dir)?;
    let artifact = attach_metadata(&component, &metadata)
        .map_err(|error| BuildError::new(format!("attach the declaration: {error}")))?;
    // The whole verdict, off the bytes the publish would carry. A
    // disagreement between the declaration and the code it describes is
    // this package's defect and it is cheaper to hear here.
    //
    // Which gate is which provenance's: a publisher may not claim the
    // total mark at all, and the protocol's own claim is read against the
    // code. Building a protocol package under the publisher's gate would
    // refuse an artifact genesis seeds, so the command has to know which
    // it is making.
    match provenance {
        Provenance::Published => admit_package(&artifact),
        Provenance::Protocol => admit_protocol_package(&artifact),
    }
    .map_err(|error| BuildError::new(error.0))?;
    Ok(artifact)
}

/// Where [`build`] writes a package's artifact.
#[must_use]
pub fn artifact_path(dir: &Path) -> PathBuf {
    dir.join("target").join("package.wasm")
}

/// Build the package in `dir` and write its artifact.
///
/// # Errors
///
/// [`BuildError`] from the build, the gate, or the write.
pub fn build(dir: &Path, provenance: Provenance) -> Result<PathBuf, BuildError> {
    let bytes = artifact(dir, provenance)?;
    let path = artifact_path(dir);
    std::fs::write(&path, &bytes)
        .map_err(|error| BuildError::new(format!("write {}: {error}", path.display())))?;
    Ok(path)
}
