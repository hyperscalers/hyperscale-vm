//! The genesis stdlib: prebuilt guest components and their effect metadata.
//!
//! Ships the account guest as a committed, componentized artifact so a
//! consumer seeds genesis state and warms its engine caches from one pinned
//! blob, with no wasm toolchain in its build. The blob is regenerated from
//! `guests/account` by the vm-harness `regenerate_stdlib` example; the
//! committed bytes — not a rebuild — are the protocol artifact, and the
//! harness's blob conformance lane runs them under both runtimes.

pub use hyperscale_vm_effects::stdlib::{
    ASKS, CLAIMS, CONFIG, FILL_CAP, VAULT, account_metadata, amm_metadata, book_metadata,
    splitter_metadata,
};
use hyperscale_vm_effects::{Hasher, PackageHash, package_hash};

/// The componentized account guest: reservation-backed `withdraw`, delta
/// `deposit`.
pub const ACCOUNT_COMPONENT: &[u8] = include_bytes!("../blobs/account.component.wasm");

/// The account package's content address under `hasher` — the key its
/// metadata publishes under and instances bind to.
#[must_use]
pub fn account_package_hash(hasher: &dyn Hasher) -> PackageHash {
    package_hash(hasher, ACCOUNT_COMPONENT)
}
