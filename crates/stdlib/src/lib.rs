//! The genesis stdlib: prebuilt guest components and their effect metadata.
//!
//! Ships each guest as a committed, componentized artifact so a consumer
//! seeds genesis state and warms its engine caches from pinned blobs, with
//! no wasm toolchain in its build. The blobs are regenerated from `guests/`
//! by the vm-harness `regenerate_stdlib` example; the committed bytes — not
//! a rebuild — are the protocol artifact, and the harness's blob
//! conformance lane runs them under both runtimes.

use std::sync::LazyLock;

use hyperscale_vm_effects::stdlib::GENESIS_PUBLISHER as GENESIS_PUBLISHER_ROLE;
pub use hyperscale_vm_effects::stdlib::{
    ASKS, CLAIMS, CONFIG, ENTROPY, FILL_CAP, UNBONDING, VAULT, account_metadata, amm_metadata,
    book_metadata, splitter_metadata, staking_metadata,
};
use hyperscale_vm_effects::{
    Hasher, NativeAddr, PackageHash, StateWrites, attach_metadata, native_address, package_hash,
    package_key,
};

/// The componentized account guest: reservation-backed `withdraw`, delta
/// `deposit`, and the randomness stamp `stamp-entropy`.
pub const ACCOUNT_COMPONENT: &[u8] = include_bytes!("../blobs/account.component.wasm");

/// The account package's content address under `hasher` — the key its
/// metadata publishes under and instances bind to.
#[must_use]
pub fn account_package_hash(hasher: &dyn Hasher) -> PackageHash {
    package_hash(hasher, ACCOUNT_COMPONENT)
}

/// The componentized stake pool guest: `stake` and `unstake`, each a
/// delegation movement and the lifecycle fact recording it.
pub const STAKING_COMPONENT: &[u8] = include_bytes!("../blobs/staking.component.wasm");

/// The stake pool package's content address under `hasher` — the key its
/// metadata publishes under and pool instances bind to.
#[must_use]
pub fn staking_package_hash(hasher: &dyn Hasher) -> PackageHash {
    package_hash(hasher, STAKING_COMPONENT)
}

/// The prefix genesis publishes the stdlib packages under.
///
/// A native address: it names a protocol role, and only a *principal*
/// address derives from a key. So no signer reaches this prefix — nothing
/// can publish beside the protocol's own packages or spend from where
/// they sit — and the code they hold moves with the protocol version
/// rather than with anything a transaction can say.
#[must_use]
pub fn genesis_publisher(hasher: &dyn Hasher) -> NativeAddr {
    native_address(hasher, GENESIS_PUBLISHER_ROLE)
}

/// The stdlib account package as a publishable artifact: the committed
/// guest blob with its effect metadata attached in the section a
/// published package carries it in.
///
/// Composition is deterministic — one committed blob, one authored
/// signature set, one frozen encoding — so every consumer holds the same
/// bytes and therefore the same content address.
static ACCOUNT_ARTIFACT: LazyLock<Vec<u8>> = LazyLock::new(|| {
    attach_metadata(ACCOUNT_COMPONENT, &account_metadata())
        .expect("the stdlib account metadata attaches to its committed blob")
});

/// The stdlib stake pool package as a publishable artifact, assembled the
/// same way and for the same reason as the account's.
static STAKING_ARTIFACT: LazyLock<Vec<u8>> = LazyLock::new(|| {
    attach_metadata(STAKING_COMPONENT, &staking_metadata())
        .expect("the stdlib stake pool metadata attaches to its committed blob")
});

/// The stdlib account artifact: the bytes a package cell commits and the
/// package's content address covers.
#[must_use]
pub fn account_artifact() -> &'static [u8] {
    &ACCOUNT_ARTIFACT
}

/// The stdlib stake pool artifact.
#[must_use]
pub fn staking_artifact() -> &'static [u8] {
    &STAKING_ARTIFACT
}

/// The protocol-defined genesis flash: each stdlib package as a committed
/// cell, under the same content address a publish would place it at.
///
/// Genesis is then the package cache's cold start in the literal sense —
/// the same projection of committed state every later block extends,
/// rather than a second source the cache is told about separately. The
/// embedder commits these writes beside its own network's allocations.
#[must_use]
pub fn genesis_writes(hasher: &dyn Hasher) -> StateWrites {
    let mut writes = StateWrites::default();
    for artifact in [account_artifact(), staking_artifact()] {
        let package = package_hash(hasher, artifact);
        let cell = package_key(hasher, genesis_publisher(hasher), package);
        writes.cells.insert(cell, Some(artifact.to_vec()));
    }
    writes
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{TestHasher, extract_metadata};

    use super::*;

    #[test]
    fn the_genesis_flash_is_one_package_cell_per_stdlib_package() {
        let writes = genesis_writes(&TestHasher);
        assert_eq!(writes.cells.len(), 2);
        for (artifact, metadata) in [
            (account_artifact(), account_metadata()),
            (staking_artifact(), staking_metadata()),
        ] {
            let cell = package_key(
                &TestHasher,
                genesis_publisher(&TestHasher),
                package_hash(&TestHasher, artifact),
            );
            assert_eq!(cell.owner, genesis_publisher(&TestHasher));
            let value = writes
                .cells
                .get(&cell)
                .expect("the package cell is written");
            let bytes = value.as_deref().expect("the flash writes, never removes");
            assert_eq!(extract_metadata(bytes).unwrap(), Some(metadata));
        }
        assert_eq!(genesis_writes(&TestHasher), writes);
    }
}
