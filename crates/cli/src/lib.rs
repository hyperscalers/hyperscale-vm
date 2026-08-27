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
//! reason they already do: a pinned nightly and one codegen unit are
//! per-workspace settings a host build must not inherit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use hyperscale_hbor::to_vec;
// The address vocabulary a caller writes on the command line, re-exported
// beside the renderer that reads one.
pub use hyperscale_vm_effects::{Address, AddressClass, PackageMetadata};
use hyperscale_vm_effects::{
    ProtocolHasher, ResourceMeta, Value, explain_resource, grants_read_config,
};
// The rendering `explain` prints, re-exported so the command reaches one
// dependency for the whole pipeline it drives.
pub use hyperscale_vm_effects::{explain, explain_method};
pub use hyperscale_vm_gate::{GateError, Provenance};
use hyperscale_vm_gate::{admit_package, admit_protocol_package, attach_metadata, decode_metadata};
use hyperscale_vm_manifest_builder::signing::{Terms, wrap_publish};
use hyperscale_vm_runtime::validate_component;
pub use hyperscale_vm_types::{NetworkId, PrincipalAddr};
use serde_json::{Value as Json, from_str};
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

/// The wasm the crate's library build produced, as the build itself
/// named it.
///
/// Read out of cargo's own artifact messages rather than found by
/// scanning a directory. A directory scan has to know two things it
/// cannot: where the target directory is — a workspace member's is the
/// workspace's, not the crate's — and which of the files in it belongs to
/// this crate, which under a shared target directory is one of many. What
/// the build says it wrote answers both, and answers them the same way
/// for a member of a workspace and for a crate that is its own root.
fn built_wasm(messages: &str) -> Result<PathBuf, BuildError> {
    let mut found: Vec<PathBuf> = messages
        .lines()
        .filter_map(|line| from_str::<Json>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .flat_map(|message| {
            let names = message["filenames"].as_array().cloned().unwrap_or_default();
            names
                .iter()
                .filter_map(Json::as_str)
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        })
        .filter(|path| path.extension().is_some_and(|it| it == "wasm"))
        .collect();
    found.sort();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(BuildError::new(
            "the build produced no wasm — the crate builds no cdylib".to_owned(),
        )),
        _ => Err(BuildError::new(format!(
            "the build produced {} wasm files, and picking would be picking arbitrarily",
            found.len()
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
    // `json-render-diagnostics` rather than plain `json`: the artifact
    // paths reach stdout for [`built_wasm`], and the diagnostics stay
    // rendered on stderr, where the linker check below reads them and
    // where an author's own build error is legible.
    let built = cargo(
        dir,
        &[
            "build",
            "--release",
            "--lib",
            "--target",
            TARGET,
            "--message-format",
            "json-render-diagnostics",
        ],
    )?;
    if !built.status.success() {
        return Err(BuildError::new(format!(
            "the package's code did not build:\n{}",
            String::from_utf8_lossy(&built.stderr)
        )));
    }
    // A linker signature mismatch is a build that succeeded and a module
    // that is wrong: two definitions claim one symbol, the toolchain's
    // wins, and the method's export is simply not there. What fails
    // otherwise is the componentization two steps on, naming a function
    // the module does not have and saying nothing about why.
    let stderr = String::from_utf8_lossy(&built.stderr);
    if let Some(mismatch) = stderr
        .lines()
        .find(|line| line.contains("signature mismatch"))
    {
        return Err(BuildError::new(format!(
            "a method's export name is one the toolchain already defines, so the module \
             carries the toolchain's definition and not the method's — rename it:\n{}",
            mismatch.trim()
        )));
    }
    let messages = String::from_utf8_lossy(&built.stdout);
    let core = std::fs::read(built_wasm(&messages)?)
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

/// What a package's own manifest says about deriving its declaration.
struct ManifestFacts {
    /// The crate's name, as the manifest spells it.
    name: String,
    /// The crate's edition, which the synthesized shim compiles under.
    edition: String,
    /// The `#[blueprint]` module, qualified by the crate:
    /// `[package.metadata.hyperscale] module = "amm_guest::amm"`.
    module: String,
    /// Where builds from this crate land.
    target_directory: PathBuf,
    /// The SDK's own crate directory, resolved through the package's
    /// dependency graph.
    sdk_dir: PathBuf,
}

/// Read the facts off `cargo metadata`, which parses the manifest the
/// way every build of it does.
fn manifest_facts(dir: &Path) -> Result<ManifestFacts, BuildError> {
    let run = cargo(dir, &["metadata", "--format-version", "1"])?;
    if !run.status.success() {
        return Err(BuildError::new(format!(
            "cargo metadata refused in {}:\n{}",
            dir.display(),
            String::from_utf8_lossy(&run.stderr)
        )));
    }
    let metadata: Json = from_str(&String::from_utf8_lossy(&run.stdout))
        .map_err(|error| BuildError::new(format!("cargo metadata is not JSON: {error}")))?;
    let manifest = dir.join("Cargo.toml").canonicalize().map_err(|error| {
        BuildError::new(format!(
            "resolve {}: {error}",
            dir.join("Cargo.toml").display()
        ))
    })?;
    let packages = metadata["packages"].as_array().cloned().unwrap_or_default();
    let own = packages
        .iter()
        .find(|package| {
            Path::new(package["manifest_path"].as_str().unwrap_or_default()) == manifest
        })
        .ok_or_else(|| {
            BuildError::new(format!("{} is not a package cargo knows", dir.display()))
        })?;
    let name = own["name"].as_str().unwrap_or_default().to_owned();
    let module = own["metadata"]["hyperscale"]["module"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            BuildError::new(format!(
                "{name} names no `#[blueprint]` module. Add\n\n\
                 [package.metadata.hyperscale]\n\
                 module = \"{}::<module>\"\n\n\
                 to its Cargo.toml — the module the `#[blueprint]` is on, qualified by \
                 the crate",
                name.replace('-', "_"),
            ))
        })?;
    let sdk_dir = packages
        .iter()
        .find(|package| package["name"] == "hyperscale-vm-sdk")
        .and_then(|package| package["manifest_path"].as_str())
        .and_then(|path| Path::new(path).parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| BuildError::new(format!("{name} does not depend on hyperscale-vm-sdk")))?;
    Ok(ManifestFacts {
        edition: own["edition"].as_str().unwrap_or("2024").to_owned(),
        target_directory: PathBuf::from(metadata["target_directory"].as_str().unwrap_or_default()),
        name,
        module,
        sdk_dir,
    })
}

/// The package's declaration, from a host build of the same crate.
///
/// The module path lives in the manifest —
/// `[package.metadata.hyperscale] module = "…"` — and the host program
/// that prints the canonical section bytes of `blueprint()` is
/// synthesized under the target directory and run there. Its output is
/// decoded here rather than trusted as text, so a program that printed
/// anything else fails now instead of at attach time.
///
/// # Errors
///
/// [`BuildError`] if the manifest names no module, the host build
/// fails, or what it printed is not canonical metadata.
pub fn declaration(dir: &Path) -> Result<PackageMetadata, BuildError> {
    let facts = manifest_facts(dir)?;
    let shim = facts
        .target_directory
        .join("hyperscale")
        .join("metadata")
        .join(&facts.name);
    let write = |path: PathBuf, body: String| {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                BuildError::new(format!("create {}: {error}", parent.display()))
            })?;
        }
        std::fs::write(&path, body)
            .map_err(|error| BuildError::new(format!("write {}: {error}", path.display())))
    };
    let dir_abs = dir
        .canonicalize()
        .map_err(|error| BuildError::new(format!("resolve {}: {error}", dir.display())))?;
    write(
        shim.join("Cargo.toml"),
        format!(
            "# Synthesized by `cargo hyperscale`: the host program that prints the\n\
             # declaration of the package beside it. Rewritten on every build.\n\
             [package]\n\
             name = \"{name}-declaration\"\n\
             version = \"0.0.0\"\n\
             edition = \"{edition}\"\n\
             publish = false\n\
             \n\
             [dependencies]\n\
             {name} = {{ path = \"{dir}\" }}\n\
             hyperscale-vm-sdk = {{ path = \"{sdk}\" }}\n\
             \n\
             [workspace]\n",
            name = facts.name,
            edition = facts.edition,
            dir = dir_abs.display(),
            sdk = facts.sdk_dir.display(),
        ),
    )?;
    write(
        shim.join("src").join("main.rs"),
        format!(
            "//! Print the package's declaration as its canonical section bytes.\n\
             \n\
             use std::io::Write as _;\n\
             \n\
             fn main() {{\n\
             \x20   let metadata = {module}::blueprint().metadata();\n\
             \x20   let bytes = hyperscale_vm_sdk::encode_metadata(&metadata)\n\
             \x20       .expect(\"a traced declaration encodes\");\n\
             \x20   std::io::stdout()\n\
             \x20       .write_all(&bytes)\n\
             \x20       .expect(\"write the declaration\");\n\
             }}\n",
            module = facts.module,
        ),
    )?;
    // The package pins its toolchain; the shim compiles the package, so
    // it compiles under the same pin.
    if let Ok(pin) = std::fs::read_to_string(dir.join("rust-toolchain.toml")) {
        write(shim.join("rust-toolchain.toml"), pin)?;
    }
    // The shim shares the package's own target directory, so the host
    // units its dependencies compile are compiled once per workspace
    // rather than once per shim.
    let run = Command::new("cargo")
        .args(["run", "--release", "--quiet"])
        .current_dir(&shim)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("CARGO_HOME")
        .env_remove("RUSTC")
        .env_remove("RUSTUP_HOME")
        .env("CARGO_TARGET_DIR", &facts.target_directory)
        .output()
        .map_err(|error| BuildError::new(format!("spawn cargo in {}: {error}", shim.display())))?;
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
    // The declaration first, and the order is the author's diagnostics.
    // Both builds compile the same module, but only the host one compiles
    // the bodies as they were written — the guest build compiles what the
    // lowering rewrote them into, and a borrow error there lands on
    // generated tokens with the attribute's span. So the build that can
    // say which line is wrong runs first, and the one that cannot is
    // reached only by a module that already type-checked.
    let metadata = declaration(dir)?;
    let component = compile(dir)?;
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
    .map_err(|refusal| BuildError::new(explain_gate_refusal(&refusal, &metadata)))?;
    Ok(artifact)
}

/// The canonical unsigned publish intent for `artifact`, as the bytes a
/// host with keys decodes, terms, signs, and submits.
///
/// The scheme is none and the terms are zero: which fee a payer offers
/// and which window they sign for are theirs to state before signing,
/// and the CLI's whole say is the body — the artifact it just admitted,
/// wrapped the way [`hyperscale_vm_manifest_builder::signing::sign`]
/// expects to receive it.
///
/// # Errors
///
/// [`BuildError`] if the envelope does not encode, which an artifact
/// within the wire caps never is.
pub fn publish_envelope(
    artifact: Vec<u8>,
    payer: PrincipalAddr,
    network: NetworkId,
) -> Result<Vec<u8>, BuildError> {
    let envelope = wrap_publish(
        artifact,
        payer,
        network,
        Terms {
            max_fee: 0,
            gas_limit: 0,
            validity_start_ms: 0,
            validity_end_ms: 0,
            message: Vec::new(),
        },
    );
    to_vec(&envelope)
        .map_err(|error| BuildError::new(format!("encode the publish envelope: {error}")))
}

/// A gate refusal, with the declaration of the method it is about
/// printed beneath it.
///
/// The sentence names a clause or a parameter by index, and an index
/// means nothing without the declaration it indexes. The gate knows which
/// method it refused, the caller holds the metadata, and `explain_method`
/// renders the numbered listing — so the three together say which line
/// the author has to change. A refusal about the package rather than one
/// method renders as its sentence and nothing else.
#[must_use]
pub fn explain_gate_refusal(refusal: &GateError, metadata: &PackageMetadata) -> String {
    let listing = refusal
        .method
        .as_deref()
        .and_then(|method| explain_method(metadata, method))
        .map_or_else(String::new, |listing| format!("\n\n{listing}"));
    format!("{refusal}{listing}")
}

/// What every resource this package issues says to a holder.
///
/// The one question a declaration cannot answer on its own. A package
/// says `withdraw = config.registrar` and cannot say what that field will
/// name; a *record* has the instance's answer folded in, so every entry
/// reads as one of two questions and whoever is deciding whether to
/// accept the resource can act on it.
///
/// `config` supplies that answer, by field name. A declaration whose
/// grants read no field needs none and is exact as written; one that does
/// is refused rather than sealed against a stand-in, because a wrong
/// address in this rendering is worse than no rendering.
///
/// `namespace` is the issuing instance where the caller has one. Without
/// it the rules are still exact — every leaf naming the issuer reads as
/// the issuer, which is a comparison against whatever namespace is used —
/// and the addresses printed are the stand-in's, which the caller is told.
///
/// # Errors
///
/// [`BuildError`] naming the configuration fields a grant reads and the
/// caller did not supply.
pub fn explain_issued(
    metadata: &PackageMetadata,
    namespace: Option<Address>,
    config: &BTreeMap<String, Address>,
) -> Result<String, BuildError> {
    let issuer = namespace.unwrap_or(STAND_IN);
    let values: Vec<Value> = metadata
        .config
        .iter()
        .map(|field| Value::Address(config.get(field).copied().unwrap_or(STAND_IN)))
        .collect();

    let mut out = String::new();
    if namespace.is_none() {
        out.push_str(
            "the issuing instance is a stand-in, so the addresses below are too — pass \
             `--instance <address>` for a component that exists\n\n",
        );
    }
    for issuance in metadata.methods.values().flat_map(|method| &method.issues) {
        let unanswered: Vec<String> = grants_read_config(&issuance.grants)
            .into_iter()
            .filter_map(|slot| metadata.config.get(slot as usize))
            .filter(|field| !config.contains_key(*field))
            .map(|field| format!("--config {field}=<address>"))
            .collect();
        if !unanswered.is_empty() {
            return Err(BuildError::new(format!(
                "the rules of `{}` read configuration this cannot know: pass {}",
                String::from_utf8_lossy(&issuance.mark),
                unanswered.join(" ")
            )));
        }
        let rules = issuance
            .grants
            .resolve(&ProtocolHasher, issuer, &values)
            .map_err(|error| {
                BuildError::new(format!("the declared grants do not seal: {error}"))
            })?;
        let record = ResourceMeta {
            namespace: issuer,
            kind: issuance.kind,
            material: vec![Value::Bytes(issuance.mark.clone()).canonical_bytes()],
            rules,
        };
        out.push_str(&explain_resource(&record, &ProtocolHasher));
        out.push('\n');
    }
    if out.trim().is_empty() {
        out.push_str("this package issues no resource\n");
    }
    Ok(out)
}

/// The instance a rendering stands on when the caller names none.
///
/// Its class is what makes it read as an instance at all; the body is
/// arbitrary, and every rendering that uses it says so.
const STAND_IN: Address = Address::new([0x11; 31], AddressClass::Component);

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
