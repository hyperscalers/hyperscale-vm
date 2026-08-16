//! Rebuild the committed guest blobs from the guest sources.
//!
//! Builds each guest with the repository toolchain, componentizes and
//! profile-validates it, and overwrites the artifact its crate embeds:
//! the protocol's own packages into `hyperscale-vm-stdlib`, the test
//! packages into `hyperscale-vm-fixtures`. Both are built on identical
//! terms — what separates them is who seeds them at genesis, not how
//! they are made.
//!
//! The committed bytes are the artifact consumers hold, and are
//! canonically Linux-built — toolchains emit the same code in different
//! function order per host OS — so roll them through
//! `scripts/regenerate-stdlib.sh`, which runs this example in the
//! canonical container, and commit the result, not a local build from
//! another OS.

use std::path::Path;

use hyperscale_vm_harness::fixtures::{build_guest, repo_root};
use hyperscale_vm_runtime::validate_component;
use wasmtime::Result;
use wasmtime::error::Context;

/// Each guest and the crate whose `blobs` directory holds it.
const BLOBS: &[(&str, &str)] = &[
    ("account", "crates/stdlib/blobs"),
    ("staking", "crates/stdlib/blobs"),
    ("lottery", "crates/fixtures/blobs"),
];

fn main() -> Result<()> {
    for (guest, blobs) in BLOBS {
        let artifact = build_guest(guest)?;
        validate_component(&artifact)
            .with_context(|| format!("{guest} component failed profile validation"))?;
        let path = repo_root()
            .join(Path::new(blobs))
            .join(format!("{guest}.component.wasm"));
        std::fs::write(&path, &artifact).with_context(|| format!("write {}", path.display()))?;
        println!("wrote {} ({} bytes)", path.display(), artifact.len());
    }
    Ok(())
}
