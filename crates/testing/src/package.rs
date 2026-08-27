//! A package as a test names it: its declaration, and where its code
//! comes from.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use hyperscale_vm_effects::PackageMetadata;
use serde_json::{Value, from_slice};

use crate::native::Dispatch;

/// One package a [`Chain`](crate::Chain) can publish.
///
/// Everything a chain could need to run it, whichever engine it has:
/// the declaration `blueprint()` traces, the crate directory a build
/// compiles from, and the bodies' own native dispatch. A test names the
/// package once and each chain takes the half it uses.
pub struct Package {
    /// The traced declaration.
    pub metadata: PackageMetadata,
    /// Where the code is, where this test can reach it.
    pub code: Code,
    /// The bodies, callable without an engine.
    pub dispatch: Dispatch,
}

/// Where a package's code comes from, as the test naming it can see.
///
/// `package!` names a module, and the crate that module lives in is not
/// always the crate the test is compiled in. Another crate of the same
/// workspace resolves through the member list; what has no crate at all
/// is a fixture module reached through a `#[path]` include, or a
/// `#[blueprint]` written inline in the test file itself — nothing on
/// disk builds those.
///
/// The other case is a fact about the test rather than an error — a
/// declaration and native bodies are the whole of what most tests want.
/// What it is not is silent: reaching for the wasm lane from there used
/// to compile the *test* crate and report that a package did not build.
pub enum Code {
    /// The package's own crate, which a build compiles.
    Crate(PathBuf),
    /// No crate this test can build the package from, and the sentence
    /// saying why.
    Unreachable(String),
}

impl Package {
    /// A package, with whatever code the naming test can reach.
    ///
    /// Called by [`package!`](crate::package), which reads both crate
    /// names off its own call site. Written out where a test names a
    /// package whose crate it knows and the macro cannot — a fixture
    /// module, or a body written by hand.
    #[must_use]
    pub fn new(metadata: PackageMetadata, code: Code, dispatch: Dispatch) -> Self {
        Self {
            metadata,
            code,
            dispatch,
        }
    }
}

/// The workspace members visible from `member`, by the underscored name
/// a Rust path carries.
///
/// `cargo metadata` once per process: the answer is a fact about the
/// workspace on disk, and every test in a binary asks about the same
/// one. A workspace this cannot read answers empty, and the lookup's
/// miss carries the sentence.
fn members(member: &Path) -> &'static BTreeMap<String, PathBuf> {
    static MEMBERS: OnceLock<BTreeMap<String, PathBuf>> = OnceLock::new();
    MEMBERS.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let Ok(output) = Command::new(cargo)
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .current_dir(member)
            .output()
        else {
            return BTreeMap::new();
        };
        let Ok(metadata) = from_slice::<Value>(&output.stdout) else {
            return BTreeMap::new();
        };
        let Some(packages) = metadata.get("packages").and_then(|p| p.as_array()) else {
            return BTreeMap::new();
        };
        packages
            .iter()
            .filter_map(|package| {
                let name = package.get("name")?.as_str()?.replace('-', "_");
                let manifest = package.get("manifest_path")?.as_str()?;
                let dir = Path::new(manifest).parent()?.to_path_buf();
                Some((name, dir))
            })
            .collect()
    })
}

/// The code behind a module named from a crate compiled as
/// `compiled_in`, rooted at `crate_dir`.
///
/// Crate names reach a macro with the hyphens a Rust path cannot carry,
/// so the comparison is over the underscored form both spellings agree
/// on. A module of another crate resolves through the workspace's own
/// member list, so a test names the crate and never spells its
/// directory.
#[must_use]
pub fn code_at(module: &'static str, compiled_in: &'static str, crate_dir: &str) -> Code {
    let wanted = module.replace('-', "_");
    if wanted == compiled_in.replace('-', "_") {
        return Code::Crate(PathBuf::from(crate_dir));
    }
    if let Some(dir) = members(Path::new(crate_dir)).get(&wanted) {
        return Code::Crate(dir.clone());
    }
    Code::Unreachable(format!(
        "`{module}` is not a crate of this workspace, so no crate builds its package — \
         a `#[blueprint]` inline in a test file runs on the native lane alone, which \
         `#[hyperscale_vm_testing::test(native)]` says outright"
    ))
}

/// The package a `#[blueprint]` module declares, rooted at the crate
/// the module lives in.
///
/// ```ignore
/// let amm = chain.publish(package!(amm_guest::amm));
/// chain.publish(package!(security_guest::security));
/// ```
///
/// The crate is the path's first segment, and its directory is the
/// workspace's own answer — a test never spells where another crate
/// sits, so a directory rename breaks nothing but the workspace file
/// that names it.
#[macro_export]
macro_rules! package {
    // Segment by segment rather than a `path` fragment: a parsed path is
    // one opaque node, and the expansion has to reach through it — to
    // the `blueprint` the module carries, and to the first segment,
    // which names the crate the module lives in.
    ($krate:ident $(:: $segment:ident)*) => {
        $crate::Package::new(
            $krate $(:: $segment)* ::blueprint().metadata(),
            $crate::code_at(
                ::core::stringify!($krate),
                ::core::env!("CARGO_PKG_NAME"),
                ::core::env!("CARGO_MANIFEST_DIR"),
            ),
            $krate $(:: $segment)* ::invoke,
        )
    };
}
