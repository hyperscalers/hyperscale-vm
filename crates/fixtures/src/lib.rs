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
pub mod peg;
pub mod perp;
pub mod registry;
pub mod shares;
pub mod splitter;

use std::sync::LazyLock;

use hyperscale_vm_effects::{Hasher, PackageHash, attach_metadata, package_hash};

/// One seedable package: its committed component, the artifact that
/// component plus its metadata makes, and the address that artifact
/// hashes to.
///
/// A macro because the three are the same three every time and the only
/// thing that varies is which guest — and a package that reached this
/// list by hand would be one whose plumbing could differ from its
/// neighbours' without anybody noticing.
macro_rules! seedable {
    ($(
        $(#[$doc:meta])*
        $module:ident => ($component:ident, $artifact:ident, $hash:ident, $blob:literal);
    )*) => {
        $(
            $(#[$doc])*
            pub const $component: &[u8] = include_bytes!(concat!("../blobs/", $blob));

            /// The package's content address under `hasher` — the key its
            /// metadata publishes under and instances bind to.
            #[must_use]
            pub fn $hash(hasher: &dyn Hasher) -> PackageHash {
                package_hash(hasher, $artifact())
            }

            /// The package as a publishable artifact: the committed guest
            /// blob with its effect metadata attached in the section a
            /// published package carries it in.
            #[must_use]
            pub fn $artifact() -> &'static [u8] {
                static ARTIFACT: LazyLock<Vec<u8>> = LazyLock::new(|| {
                    attach_metadata($component, &$module::metadata())
                        .expect("the metadata attaches to its committed blob")
                });
                &ARTIFACT
            }
        )*

        /// The fixture artifacts an embedder seeds as a set.
        ///
        /// What a simulation needs to start a network that already has
        /// something to do: a pool, a book, a lending market, a
        /// perpetual, a share vault, a splitter and a lottery. Every one
        /// of them publishes from committed bytes rather than through a
        /// test, which is the difference between a package a simulation
        /// can seed and one only the corpus can reach.
        #[must_use]
        pub fn artifacts() -> Vec<&'static [u8]> {
            vec![$($artifact()),*]
        }
    };
}

seedable! {
    /// The constant-product pool: swaps against a pair, and claims on it.
    amm => (AMM_COMPONENT, amm_artifact, amm_package_hash, "amm.component.wasm");
    /// The order book: makers rest asks on a tick ladder, takers walk it.
    book => (BOOK_COMPONENT, book_artifact, book_package_hash, "book.component.wasm");
    /// The lending market: collateral against debt, over a carried index.
    lending => (LENDING_COMPONENT, lending_artifact, lending_package_hash, "lending.component.wasm");
    /// The lottery: `enter` buys a ticket, `close` seals the round, and
    /// `settle` opens the seal to pick a winner.
    lottery => (LOTTERY_COMPONENT, lottery_artifact, lottery_package_hash, "lottery.component.wasm");
    /// The fee splitter: revenue in, three configured shares out.
    payouts => (PAYOUTS_COMPONENT, payouts_artifact, payouts_package_hash, "payouts.component.wasm");
    /// The redemption window: a stable against a reserve, at a price
    /// that moves both ways.
    peg => (PEG_COMPONENT, peg_artifact, peg_package_hash, "peg.component.wasm");
    /// The perpetual: margin against a size, marked and funded.
    perp => (PERP_COMPONENT, perp_artifact, perp_package_hash, "perp.component.wasm");
    /// The share vault: assets in, shares out, at whatever the pool is worth.
    shares => (SHARES_COMPONENT, shares_artifact, shares_package_hash, "shares.component.wasm");
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{PackageMetadata, TestHasher, extract_metadata};

    use super::*;

    /// Every seedable package, with the metadata its address covers.
    fn seeded() -> Vec<(&'static [u8], PackageMetadata)> {
        vec![
            (amm_artifact(), amm::metadata()),
            (book_artifact(), book::metadata()),
            (lending_artifact(), lending::metadata()),
            (lottery_artifact(), lottery::metadata()),
            (payouts_artifact(), payouts::metadata()),
            (peg_artifact(), peg::metadata()),
            (perp_artifact(), perp::metadata()),
            (shares_artifact(), shares::metadata()),
        ]
    }

    #[test]
    fn every_artifact_carries_the_metadata_its_address_covers() {
        for (artifact, metadata) in seeded() {
            assert_eq!(extract_metadata(artifact).unwrap(), Some(metadata));
        }
    }

    /// The attached section is what an address covers, so a bare
    /// component addresses differently from the package it is half of.
    #[test]
    fn a_bare_component_is_not_the_package() {
        assert_eq!(
            lottery_package_hash(&TestHasher),
            package_hash(&TestHasher, lottery_artifact())
        );
        assert_ne!(
            lottery_package_hash(&TestHasher),
            package_hash(&TestHasher, LOTTERY_COMPONENT)
        );
    }

    #[test]
    fn the_fixture_set_is_every_artifact_this_crate_ships() {
        let shipped: Vec<_> = seeded().into_iter().map(|(artifact, _)| artifact).collect();
        assert_eq!(artifacts(), shipped);
    }
}
