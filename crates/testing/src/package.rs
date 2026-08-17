//! A package as a test names it: its declaration, and where its code
//! comes from.

use std::path::PathBuf;

use hyperscale_vm_effects::PackageMetadata;

/// One package a [`Chain`](crate::Chain) can publish.
///
/// The declaration is the package's own — `blueprint().metadata()`, the
/// same trace the build attaches to the artifact — and the crate
/// directory is how a chain that needs the compiled component finds one
/// to compile. A chain that runs bodies natively reads only the
/// declaration.
pub struct Package {
    /// The traced declaration.
    pub metadata: PackageMetadata,
    /// The package crate's root, as `CARGO_MANIFEST_DIR` names it.
    pub crate_dir: PathBuf,
}

impl Package {
    /// A package rooted at `crate_dir`.
    ///
    /// Called by [`package!`](crate::package), which supplies the
    /// directory from the call site: the crate under test is the one the
    /// test is compiled in, and only the macro's expansion is there.
    #[must_use]
    pub fn new(metadata: PackageMetadata, crate_dir: impl Into<PathBuf>) -> Self {
        Self {
            metadata,
            crate_dir: crate_dir.into(),
        }
    }
}

/// The package a `#[blueprint]` module declares, rooted at the crate the
/// macro is written in.
///
/// ```ignore
/// let amm = chain.publish(package!(amm_guest::amm));
/// ```
#[macro_export]
macro_rules! package {
    // Token trees rather than a `path` fragment: a parsed path is one
    // opaque node, and the expansion has to reach through it to the
    // `blueprint` the module carries.
    ($($module:tt)*) => {
        $crate::Package::new(
            $($module)*::blueprint().metadata(),
            ::core::env!("CARGO_MANIFEST_DIR"),
        )
    };
}
