//! Prebuilt test packages: guests a network may seed at genesis, and
//! that production never does.
//!
//! These are packages in every sense the protocol cares about — a
//! componentized guest, authored effect metadata, one content address —
//! and in no sense the protocol depends on. One module per package, on
//! the same terms as the protocol's own. Nothing here is a protocol
//! artifact; what separates them from [`hyperscale_vm_stdlib`]'s account
//! and stake pool is not their shape but who seeds them, which is a
//! decision the embedder makes per network.
//!
//! The separation is the crate boundary rather than a flag, so a fixture
//! reaching production genesis takes a deliberate dependency to get
//! there. An embedder passes the protocol set on a real network and this
//! set beside it on a test or simulation one.
//!
//! The blobs are regenerated from `guests/` by the vm-harness
//! `regenerate_stdlib` example, on the same terms the protocol's are: the
//! committed bytes are what consumers hold, and the harness's blob
//! conformance lane runs them under both runtimes.
//!
//! Three guards hold hand-authored metadata to what the modules do:
//! `effects/tests/authored.rs` sweeps every package's declarations
//! against the admission rules, `harness/tests/wrappers.rs` holds each
//! generated wrapper to the signature it wraps, and the harness corpus
//! executes the packages end to end on both runtimes. A new hand-authored
//! module joins all three or its metadata can drift from its bodies with
//! nothing to say so.
//!
//! [`hyperscale_vm_stdlib`]: https://docs.rs/hyperscale-vm-stdlib

pub mod amm;
pub mod book;
pub mod grammar;
pub mod lending;
pub mod lottery;
pub mod nf;
pub mod payouts;
pub mod registry;
pub mod shares;
pub mod splitter;

use std::sync::LazyLock;

use hyperscale_vm_effects::{Hasher, PackageHash, attach_metadata, package_hash};

/// The componentized lottery guest: `enter` buys a ticket into the pot,
/// `close` seals the round, and `settle` opens the seal to pick a
/// winner.
pub const LOTTERY_COMPONENT: &[u8] = include_bytes!("../blobs/lottery.component.wasm");

/// The lottery package's content address under `hasher` — the key its
/// metadata publishes under and instances bind to.
#[must_use]
pub fn lottery_package_hash(hasher: &dyn Hasher) -> PackageHash {
    package_hash(hasher, lottery_artifact())
}

/// The lottery package as a publishable artifact: the committed guest
/// blob with its effect metadata attached in the section a published
/// package carries it in.
static LOTTERY_ARTIFACT: LazyLock<Vec<u8>> = LazyLock::new(|| {
    attach_metadata(LOTTERY_COMPONENT, &lottery::metadata())
        .expect("the lottery metadata attaches to its committed blob")
});

/// The lottery artifact: the bytes a package cell commits and the
/// package's content address covers.
#[must_use]
pub fn lottery_artifact() -> &'static [u8] {
    &LOTTERY_ARTIFACT
}

/// The fixture artifacts an embedder seeds as a set: only the lottery
/// today — the other fixtures publish through tests rather than ship as
/// seedable artifacts.
#[must_use]
pub fn artifacts() -> Vec<&'static [u8]> {
    vec![lottery_artifact()]
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{TestHasher, extract_metadata};

    use super::*;

    #[test]
    fn the_artifact_carries_the_metadata_its_address_covers() {
        let artifact = lottery_artifact();
        assert_eq!(
            extract_metadata(artifact).unwrap(),
            Some(lottery::metadata())
        );
        // The attached section is what the address covers, so the bare
        // component addresses differently from the package.
        assert_eq!(
            lottery_package_hash(&TestHasher),
            package_hash(&TestHasher, artifact)
        );
        assert_ne!(
            lottery_package_hash(&TestHasher),
            package_hash(&TestHasher, LOTTERY_COMPONENT)
        );
    }

    #[test]
    fn the_fixture_set_is_every_artifact_this_crate_ships() {
        assert_eq!(artifacts(), vec![lottery_artifact()]);
    }
}
