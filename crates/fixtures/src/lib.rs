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

/// A package derived from its guest crate, and the four items every
/// fixture module reaches it through.
///
/// The guest source is included in place rather than copied here,
/// because a second copy is the drift the derivation exists to remove.
/// What a fixture module adds beside this is its own: the codes its
/// methods decline with, the marks it issues, the records its instances
/// carry. What it does not add is any of this, which was thirteen copies
/// that had already drifted three ways — three modules re-exported
/// `blueprint` and ten did not, two omitted `invoke`, and one traced its
/// metadata through a path instead of the re-export beside it.
///
/// The source path is spelled out because `#[path]` takes a literal.
macro_rules! guest {
    ($module:ident, $source:literal) => {
        #[path = $source]
        mod package;

        /// The package's traced declaration.
        pub use package::$module::blueprint;
        /// The call surface a client reaches its methods through.
        pub use package::$module::client::*;
        /// The package's own bodies, dispatched natively.
        ///
        /// The same module the declaration is traced from, so a lane
        /// running this is running the code the artifact was built from.
        pub use package::$module::invoke;

        /// The package's declaration, traced from its own module.
        #[must_use]
        pub fn metadata() -> ::hyperscale_vm_effects::PackageMetadata {
            blueprint().metadata()
        }
    };
}

pub mod amm;
pub mod book;
pub mod capped;
pub mod custodian;
pub mod flashloan;
pub mod grammar;
pub mod lending;
pub mod lottery;
pub mod nf;
pub mod payouts;
pub mod peg;
pub mod perp;
pub mod registry;
pub mod security;
pub mod shares;

use std::sync::LazyLock;

use hyperscale_vm_effects::{
    DeclaredPackages, Hasher, PackageHash, PackageMetadata, attach_metadata, package_hash,
};

/// Every package this crate declares, and for the ones that ship as
/// artifacts, the three items a consumer reaches them through.
///
/// One list because a package is one thing. What a corpus sweep wants —
/// every declaration — and what an embedder wants — every committed blob
/// — are two readings of it rather than two lists to keep agreeing, and
/// the second list is the one that quietly falls behind: the commit that
/// added the seventh package left three of six registrations unmade.
///
/// A module named without a blob is one nothing seeds. It is still
/// declared, still swept, and still snapshotted; it simply has no
/// committed bytes for a consumer to publish.
macro_rules! packages {
    ($(
        $module:ident $(=> ($component:ident, $artifact:ident, $hash:ident, $blob:literal))?;
    )*) => {
        $(
            $(
                /// The committed component bytes: the guest as its
                /// canonical builder produced it, before its declaration
                /// is attached.
                pub const $component: &[u8] = include_bytes!(concat!("../blobs/", $blob));

                /// The package's content address under `hasher` — the key
                /// its metadata publishes under and instances bind to.
                #[must_use]
                pub fn $hash(hasher: &dyn Hasher) -> PackageHash {
                    package_hash(hasher, $artifact())
                }

                /// The package as a publishable artifact: the committed
                /// guest blob with its effect metadata attached in the
                /// section a published package carries it in.
                #[must_use]
                pub fn $artifact() -> &'static [u8] {
                    static ARTIFACT: LazyLock<Vec<u8>> = LazyLock::new(|| {
                        attach_metadata($component, &$module::metadata())
                            .expect("the metadata attaches to its committed blob")
                    });
                    &ARTIFACT
                }
            )?
        )*

        /// Every package here, by name, with the declaration it traces.
        ///
        /// What the corpus sweeps read: adding a module to this list is
        /// enough to have its declaration checked and its snapshot
        /// committed, so neither sweep can be the one somebody forgot.
        pub const DECLARED: DeclaredPackages = &[
            $((stringify!($module), $module::metadata as fn() -> PackageMetadata),)*
        ];

        /// The ones that ship as committed bytes, by name, with those
        /// bytes.
        ///
        /// What the digest gate reads to prove a blob is what its source
        /// builds, and what the regenerate example reads to know which
        /// guests to build.
        pub const SHIPPED: &[(&str, &[u8])] = &[
            $($((stringify!($module), $component),)?)*
        ];

        /// The fixture artifacts an embedder seeds as a set.
        ///
        /// What a simulation needs to start a network that already has
        /// something to do. Every one of them publishes from committed
        /// bytes rather than through a test, which is the difference
        /// between a package a simulation can seed and one only the
        /// corpus can reach.
        #[must_use]
        pub fn artifacts() -> Vec<&'static [u8]> {
            vec![$($($artifact(),)?)*]
        }

        /// Every shipped package's artifact, with the metadata its
        /// address covers.
        #[must_use]
        pub fn seeded() -> Vec<(&'static [u8], PackageMetadata)> {
            vec![$($(($artifact(), $module::metadata()),)?)*]
        }
    };
}

packages! {
    // The constant-product pool: swaps against a pair, and claims on it.
    amm => (AMM_COMPONENT, amm_artifact, amm_package_hash, "amm.component.wasm");
    // The order book: makers rest asks on a tick ladder, takers walk it.
    book => (BOOK_COMPONENT, book_artifact, book_package_hash, "book.component.wasm");
    // Capped supply, deflationary supply, and delegated minting — the
    // three shapes that need issuance to be a rule rather than a fact
    // about the issuer's address.
    capped;
    // The component that holds value and declares no rule about it.
    // Declared and never seeded: what it is for is what admission makes
    // of its declaration, which needs no network to establish.
    custodian;
    // The flash lender: value that cannot come to rest, so the loan
    // cannot outlive the transaction that took it.
    flashloan => (FLASHLOAN_COMPONENT, flashloan_artifact, flashloan_package_hash, "flashloan.component.wasm");
    // The shape corpus: every form the grammar admits, as a package that
    // has to execute them. Declared and never seeded — what it is for is
    // the derivation, not a network.
    grammar;
    // The lending market: collateral against debt, over a carried index.
    lending => (LENDING_COMPONENT, lending_artifact, lending_package_hash, "lending.component.wasm");
    // The lottery: `enter` buys a ticket, `close` seals the round, and
    // `settle` opens the seal to pick a winner.
    lottery => (LOTTERY_COMPONENT, lottery_artifact, lottery_package_hash, "lottery.component.wasm");
    // The non-fungible issuer, whose declaration is written out beside
    // it rather than traced.
    nf;
    // The fee splitter: revenue in, three configured shares out.
    payouts => (PAYOUTS_COMPONENT, payouts_artifact, payouts_package_hash, "payouts.component.wasm");
    // The redemption window: a stable against a reserve, at a price
    // that moves both ways.
    peg => (PEG_COMPONENT, peg_artifact, peg_package_hash, "peg.component.wasm");
    // The perpetual: margin against a size, marked and funded.
    perp => (PERP_COMPONENT, perp_artifact, perp_package_hash, "perp.component.wasm");
    // The registry, hand-authored alongside its declaration.
    registry;
    // The share class whose holders are a register, and the register
    // entry itself. The declaring end of the movement seam, where the
    // custodian is the declaring-nothing end.
    security => (SECURITY_COMPONENT, security_artifact, security_package_hash, "security.component.wasm");
    // The share vault: assets in, shares out, at whatever the pool is worth.
    shares => (SHARES_COMPONENT, shares_artifact, shares_package_hash, "shares.component.wasm");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_vm_effects::{TestHasher, extract_metadata};

    use super::*;

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

    /// Every blob on disk is one the list names.
    ///
    /// The other direction is free — a name without a file fails to
    /// compile, because the bytes are included at build time. This is the
    /// direction that can go quiet: a committed blob nothing names is a
    /// blob no digest test proves and no consumer can reach, which is
    /// exactly how six of nine came to be ungated.
    #[test]
    fn every_committed_blob_is_a_package_this_crate_ships() {
        let named: BTreeSet<_> = SHIPPED
            .iter()
            .map(|(name, _)| format!("{name}.component.wasm"))
            .collect();
        let on_disk: BTreeSet<_> = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/blobs"))
            .expect("the blobs directory")
            .map(|entry| entry.expect("a directory entry").file_name())
            .filter_map(|name| name.to_str().map(str::to_owned))
            .filter(|name| std::path::Path::new(name).extension() == Some("wasm".as_ref()))
            .collect();
        assert_eq!(on_disk, named);
    }

    /// A package that ships is a package that is declared.
    #[test]
    fn everything_shipped_is_everything_declared_or_less() {
        let declared: BTreeSet<_> = DECLARED.iter().map(|(name, _)| *name).collect();
        for (name, _) in SHIPPED {
            assert!(declared.contains(name), "{name} ships and is not declared");
        }
    }
}
