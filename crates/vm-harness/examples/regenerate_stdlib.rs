//! Rebuild the committed stdlib blobs from the guest sources.
//!
//! Builds each stdlib guest with the repository toolchain, componentizes
//! and profile-validates it, and overwrites the artifact
//! `hyperscale-vm-stdlib` embeds. The committed bytes are the protocol
//! artifact — run this only to deliberately roll the stdlib, and commit
//! the result.

use hyperscale_vm_harness::fixtures::{build_guest, repo_root};
use hyperscale_vm_runtime::validate_component;
use wasmtime::Result;
use wasmtime::error::Context;

fn main() -> Result<()> {
    for guest in ["account", "staking"] {
        let artifact = build_guest(guest)?;
        validate_component(&artifact)
            .with_context(|| format!("{guest} component failed profile validation"))?;
        let path = repo_root()
            .join("crates/vm-stdlib/blobs")
            .join(format!("{guest}.component.wasm"));
        std::fs::write(&path, &artifact).with_context(|| format!("write {}", path.display()))?;
        println!("wrote {} ({} bytes)", path.display(), artifact.len());
    }
    Ok(())
}
