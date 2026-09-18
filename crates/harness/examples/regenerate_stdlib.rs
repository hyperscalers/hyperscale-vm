//! Rebuild the committed guest blobs from the guest sources.
//!
//! Builds each guest through `cargo hyperscale`'s own compile step —
//! which profile-validates — and overwrites the
//! artifact its crate embeds:
//! the protocol's own packages into `hyperscale-vm-stdlib`, the test
//! packages into `hyperscale-vm-fixtures`. Both are built on identical
//! terms — what separates them is who seeds them at genesis, not how
//! they are made.
//!
//! `--check` compares instead of writing, naming every blob that is not
//! what its source builds and showing where the two diverge. Writing and
//! checking are the same build in the same place on purpose: the bytes
//! are reproducible only within the canonical builder, so the only
//! environment that can judge them is the one that makes them.
//!
//! Run it through `scripts/regenerate-stdlib.sh`, which is what puts it
//! in that environment; started anywhere else it refuses rather than
//! writing bytes nobody can reproduce.

use std::path::Path;

use hyperscale_vm_fixtures::SHIPPED as FIXTURES_SHIPPED;
use hyperscale_vm_harness::fixtures::{build_guest, repo_root};
use hyperscale_vm_stdlib::SHIPPED as STDLIB_SHIPPED;
use wasmtime::Result;
use wasmtime::error::{Context, Error};

/// Where the canonical builder mounts the repository.
///
/// The bytes depend on it. Cargo derives each unit's `-C metadata` from
/// its package id, and a path dependency's package id carries its
/// absolute path, so the directory salts the symbol hashes that the
/// emitted function order follows. `trim-paths` and `--strip-all` keep
/// the path out of the artifact's contents; neither keeps it out of the
/// arrangement. One directory owns the bytes as much as one operating
/// system does, and it is the one `scripts/regenerate-stdlib.sh` mounts.
const CANONICAL_ROOT: &str = "/work";

/// Each guest and the crate whose `blobs` directory holds it.
///
/// Read off the two crates' own lists: what ships is what they say
/// ships, so a blob this never writes is one nothing includes.
fn blobs() -> Vec<(&'static str, &'static str)> {
    let protocol = STDLIB_SHIPPED
        .iter()
        .map(|(name, _)| (*name, "crates/stdlib/blobs"));
    let fixtures = FIXTURES_SHIPPED
        .iter()
        .map(|(name, _)| (*name, "crates/fixtures/blobs"));
    protocol.chain(fixtures).collect()
}

/// Off the canonical builder there is nothing to write that anyone could
/// reproduce, so the only honest outcome is a refusal naming the script
/// that does it properly.
fn refusal() -> Error {
    Error::msg(format!(
        "the committed blobs are canonically built on Linux under {CANONICAL_ROOT}: toolchains \
         emit the same code in a different function order per host OS, and cargo salts each \
         crate's symbol hashes with the absolute path it builds from, so a build elsewhere \
         would differ from the bytes consumers hold without differing in behaviour. Run \
         `scripts/regenerate-stdlib.sh`, which builds them in that environment."
    ))
}

fn main() -> Result<()> {
    let root = repo_root();
    if !cfg!(target_os = "linux") || root != Path::new(CANONICAL_ROOT) {
        return Err(refusal());
    }
    let checking = std::env::args().any(|argument| argument == "--check");
    let mut diverged = Vec::new();
    for (guest, directory) in blobs() {
        let built = build_guest(guest)?;
        let path = root.join(directory).join(format!("{guest}.wasm"));
        if !checking {
            std::fs::write(&path, &built).with_context(|| format!("write {}", path.display()))?;
            println!("wrote {} ({} bytes)", path.display(), built.len());
            continue;
        }
        let committed = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        if committed == built {
            println!("{guest} matches ({} bytes)", built.len());
            continue;
        }
        println!(
            "{guest}: committed {} bytes, built {} bytes\n{}",
            committed.len(),
            built.len(),
            diff_report(&committed, &built),
        );
        diverged.push(guest);
    }
    if diverged.is_empty() {
        return Ok(());
    }
    Err(Error::msg(format!(
        "not what their sources build: {} — run `scripts/regenerate-stdlib.sh` and commit the \
         result",
        diverged.join(", ")
    )))
}

/// Hex context around the first differing byte ranges, so a mismatch on
/// a machine whose artifact we cannot fetch (CI) still shows what its
/// build produced where it diverges.
fn diff_report(committed: &[u8], built: &[u8]) -> String {
    use std::fmt::Write;
    const MAX_RANGES: usize = 8;
    const CONTEXT: usize = 8;
    let n = committed.len().min(built.len());
    let mut out = String::new();
    let mut i = 0;
    let mut shown = 0;
    while i < n && shown < MAX_RANGES {
        if committed[i] == built[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && committed[i] != built[i] {
            i += 1;
        }
        let lo = start.saturating_sub(CONTEXT);
        let hi = (i + CONTEXT).min(n);
        let hex = |b: &[u8]| {
            b.iter().fold(String::new(), |mut s, x| {
                let _ = write!(s, "{x:02x}");
                s
            })
        };
        let _ = writeln!(
            out,
            "  diff at {start}..{i}:\n    committed[{lo}..{hi}] = {}\n    built    [{lo}..{hi}] = {}",
            hex(&committed[lo..hi]),
            hex(&built[lo..hi]),
        );
        shown += 1;
    }
    if committed.len() != built.len() {
        let _ = writeln!(
            out,
            "  lengths differ: committed {} vs built {}",
            committed.len(),
            built.len(),
        );
    }
    out
}
