//! The address derivations' input corpus.
//!
//! The derivations are consensus content: two implementations that
//! disagree about an address disagree about who owns a substate. The
//! inputs live here once so that every hasher the protocol runs pins the
//! same cases rather than a copy of them that can drift — this crate's
//! [`TestHasher`](crate::hash::TestHasher) and, from the consensus
//! workspace, the protocol hash itself.

use std::fmt::Write as _;

use hyperscale_vm_types::{Address, AddressClass, SchemeId};

use crate::hash::{Hash32, Hasher};
use crate::metadata::PackageHash;
use crate::resource::ResourceKind;
use crate::types::{
    component_address, config_hash, native_address, package_address, principal_address,
    resource_address,
};
use crate::vocabulary::XRD;

/// The configuration leaf bytes the component vector commits to.
pub const CONFIG_LEAF: &[u8] = b"hyperscale-vm/vectors/config-leaf";

/// The salt the component vector is created under: a creating
/// transaction's fresh id.
pub const SALT: Hash32 = Hash32([0x5a; 32]);

/// The published artifact the package and component vectors name.
pub const PACKAGE: PackageHash = PackageHash(Hash32([0x70; 32]));

/// Every derivation under `hasher`, named.
///
/// The names are stable and are what a pinned table keys on, so a case
/// added here shows up as a missing row rather than a shifted one.
#[must_use]
pub fn address_vectors(hasher: &dyn Hasher) -> Vec<(&'static str, Address)> {
    let config = config_hash(hasher, CONFIG_LEAF);
    let minter = component_address(hasher, PACKAGE, config, SALT);
    vec![
        (
            "principal/ed25519/a",
            principal_address(hasher, SchemeId::ED25519, &[0xa1; 32]).into(),
        ),
        (
            "principal/ed25519/b",
            principal_address(hasher, SchemeId::ED25519, &[0xb2; 32]).into(),
        ),
        ("component/salted", minter.into()),
        ("package/content", package_address(hasher, PACKAGE).into()),
        (
            "resource/minted",
            resource_address(hasher, minter, ResourceKind::Fungible, &[b"unit".to_vec()]).into(),
        ),
        (
            "resource/minted-nf",
            resource_address(
                hasher,
                minter,
                ResourceKind::NonFungible,
                &[b"unit".to_vec()],
            )
            .into(),
        ),
        ("native/xrd", native_address(hasher, XRD).into()),
    ]
}

/// The vectors as `name = hex` lines, for pinning against a literal
/// table.
#[must_use]
pub fn address_vector_lines(hasher: &dyn Hasher) -> Vec<String> {
    address_vectors(hasher)
        .into_iter()
        .map(|(name, address)| {
            let hex = address
                .to_bytes()
                .iter()
                .fold(String::with_capacity(64), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                });
            format!("{name} = {hex}")
        })
        .collect()
}

/// The class each named vector must carry.
///
/// A derivation that lands under the wrong tag is the failure that would
/// otherwise surface as a client accepting a pool where it wanted an
/// account, so the corpus asserts it on every hasher.
#[must_use]
pub fn expected_classes() -> Vec<(&'static str, AddressClass)> {
    vec![
        ("principal/ed25519/a", AddressClass::Principal),
        ("principal/ed25519/b", AddressClass::Principal),
        ("component/salted", AddressClass::Component),
        ("package/content", AddressClass::Package),
        ("resource/minted", AddressClass::Resource),
        ("resource/minted-nf", AddressClass::Resource),
        ("native/xrd", AddressClass::Native),
    ]
}
