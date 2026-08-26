//! A package as a test names it: its declaration, and where its code
//! comes from.

use std::path::PathBuf;

use hyperscale_vm_effects::PackageMetadata;

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
/// always the crate the test is compiled in: a fixture module reaches a
/// guest through a `#[path]` include, and a `#[blueprint]` can be
/// written inline in the test file itself. `CARGO_MANIFEST_DIR` is the
/// package's own crate only when the two agree, and only then is there
/// a crate to build.
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

/// The code behind a module named from a crate compiled as
/// `compiled_in`, rooted at `crate_dir`.
///
/// Crate names reach a macro with the hyphens a Rust path cannot carry,
/// so the comparison is over the underscored form both spellings agree
/// on.
#[must_use]
pub fn code_at(module: &'static str, compiled_in: &'static str, crate_dir: &str) -> Code {
    if module.replace('-', "_") == compiled_in.replace('-', "_") {
        return Code::Crate(PathBuf::from(crate_dir));
    }
    Code::Unreachable(format!(
        "`{module}` is not the crate this test is compiled in (`{compiled_in}`), so \
         `CARGO_MANIFEST_DIR` names a crate that builds no package"
    ))
}

/// The package a `#[blueprint]` module declares, rooted at the crate the
/// macro is written in.
///
/// ```ignore
/// let amm = chain.publish(package!(amm_guest::amm));
/// ```
///
/// A test needing a second package names where that crate is, relative
/// to its own — the wasm lane builds a package from its crate, and no
/// crate can be asked where another one's source sits:
///
/// ```ignore
/// chain.publish(package!(security_guest::security at "../security"));
/// ```
#[macro_export]
macro_rules! package {
    ($krate:ident $(:: $segment:ident)* at $dir:literal) => {
        $crate::Package::new(
            $krate $(:: $segment)* ::blueprint().metadata(),
            $crate::Code::Crate(
                ::std::path::Path::new(::core::env!("CARGO_MANIFEST_DIR")).join($dir),
            ),
            $krate $(:: $segment)* ::invoke,
        )
    };
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
