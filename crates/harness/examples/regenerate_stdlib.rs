//! Rebuild the committed guest blobs from the guest sources.
//!
//! Builds each guest through `cargo hyperscale`'s own compile step —
//! which componentizes and profile-validates — and overwrites the
//! artifact its crate embeds:
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
//! another OS. Running it anywhere else refuses rather than writing
//! bytes nobody can reproduce.

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use hyperscale_vm_harness::fixtures::{build_guest, repo_root};
#[cfg(not(target_os = "linux"))]
use wasmtime::Error;
use wasmtime::Result;
#[cfg(target_os = "linux")]
use wasmtime::error::Context;

/// Each guest and the crate whose `blobs` directory holds it.
#[cfg(target_os = "linux")]
const BLOBS: &[(&str, &str)] = &[
    ("account", "crates/stdlib/blobs"),
    ("staking", "crates/stdlib/blobs"),
    ("amm", "crates/fixtures/blobs"),
    ("book", "crates/fixtures/blobs"),
    ("lending", "crates/fixtures/blobs"),
    ("lottery", "crates/fixtures/blobs"),
    ("payouts", "crates/fixtures/blobs"),
    ("peg", "crates/fixtures/blobs"),
    ("perp", "crates/fixtures/blobs"),
    ("shares", "crates/fixtures/blobs"),
];

/// Off the canonical host there is nothing to write that anyone could
/// reproduce, so the only honest outcome is a refusal naming the script
/// that does it properly.
#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    Err(Error::msg(
        "the committed blobs are canonically Linux-built: toolchains emit the same code in \
         different function order per host OS, so a local build here would differ from the \
         bytes consumers hold without differing in behaviour. Run \
         `scripts/regenerate-stdlib.sh`, which builds them in that environment.",
    ))
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    for (guest, blobs) in BLOBS {
        let artifact = build_guest(guest)?;
        let path = repo_root()
            .join(Path::new(blobs))
            .join(format!("{guest}.component.wasm"));
        std::fs::write(&path, &artifact).with_context(|| format!("write {}", path.display()))?;
        println!("wrote {} ({} bytes)", path.display(), artifact.len());
    }
    Ok(())
}
