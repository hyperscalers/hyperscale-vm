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
    /// The package crate's root, as `CARGO_MANIFEST_DIR` names it.
    pub crate_dir: PathBuf,
    /// The bodies, callable without an engine.
    pub dispatch: Dispatch,
}

impl Package {
    /// A package rooted at `crate_dir`.
    ///
    /// Called by [`package!`](crate::package), which supplies the
    /// directory from the call site: the crate under test is the one the
    /// test is compiled in, and only the macro's expansion is there.
    #[must_use]
    pub fn new(
        metadata: PackageMetadata,
        crate_dir: impl Into<PathBuf>,
        dispatch: Dispatch,
    ) -> Self {
        Self {
            metadata,
            crate_dir: crate_dir.into(),
            dispatch,
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
            $($module)*::invoke,
        )
    };
}
