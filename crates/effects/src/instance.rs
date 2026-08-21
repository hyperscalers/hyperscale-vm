//! Instance target resolution: the creation-fixed record a component's
//! address derives, and the registry a routing pass reads targets from.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;

use hyperscale_hbor::{EncodeError, Hbor, to_vec};
use hyperscale_vm_types::{Address, CallTarget, ComponentAddr};
use thiserror::Error;

use crate::hash::{Hash32, Hasher};
use crate::metadata::PackageHash;
use crate::types::{Value, component_address, config_hash};

/// Why a call target does not resolve to a method: the chain from an
/// address through its record and package to the named signature, broken
/// at the first absent link.
///
/// One vocabulary for every resolver — admission and routing walk the
/// same chain and refuse it identically.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ResolveError {
    /// A call target with no registered instance.
    #[error("no instance at {0:?}")]
    UnknownInstance(Address),
    /// An instance whose package is not in the metadata cache.
    #[error("no package {0:?} in the metadata cache")]
    UnknownPackage(PackageHash),
    /// A method the target package does not declare.
    #[error("package {package:?} has no method `{method}`")]
    UnknownMethod {
        /// The package consulted.
        package: PackageHash,
        /// The method requested.
        method: String,
    },
}

/// An instance's creation-fixed record: the package it runs, the
/// configuration it was created under, and the salt separating it from
/// every other instance of the same two.
///
/// A presented claim rather than trusted state. A component's address is
/// the hash of exactly these three, so a holder checks the record by
/// recomputing the address rather than by consulting a registry — which
/// is what lets any shard verify any target with no foreign reads, and
/// what makes a false package claim a hash collision rather than a
/// lookup that disagrees.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct InstanceMeta {
    /// The package the instance runs.
    pub package: PackageHash,
    /// The instance's creation-fixed configuration fields.
    #[hbor(max = MAX_CONFIG_FIELDS)]
    pub config: Vec<Value>,
    /// The creating transaction's fresh id, which separates two
    /// instances made from one package under one configuration.
    pub salt: Hash32,
}

/// The bound on an instance's configuration fields. A wire bound.
///
/// A signature indexes them positionally with a `u32`, and the whole list
/// is hashed into the instance's address, so the cap is what keeps a
/// presented certificate's decode bounded by its own declaration.
pub const MAX_CONFIG_FIELDS: usize = 64;

impl InstanceMeta {
    /// The configuration's canonical encoding — the preimage the
    /// address derivation hashes.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] if the configuration is past the vocabulary's own
    /// caps, which no admitted creation can have produced.
    pub fn config_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec(&self.config)
    }

    /// The configuration leaf's stored bytes — the canonical encoding of
    /// the whole record, which instantiation grants into the `CONFIG`
    /// cell.
    ///
    /// The leaf holds all three parts rather than the configuration
    /// alone: routing resolves a target to a package to get the
    /// signature it evaluates, and a hashed address gives nothing back —
    /// the record in the leaf is what answers. Holding all three also
    /// makes the leaf self-verifying: recompute [`Self::address`] from
    /// its contents and compare to the owner it sits under.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] if the configuration is past the vocabulary's own
    /// caps, which no admitted creation can have produced.
    pub fn leaf_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec(self)
    }

    /// The address this record derives.
    ///
    /// The creation side of the same equality [`Self::derives`] checks:
    /// an instance's address is a function of what it is, so whoever
    /// creates one computes the address rather than choosing it. The class
    /// is not a claim about the result either — a record derives a
    /// component and nothing else, so the derivation answers with one.
    ///
    /// # Panics
    ///
    /// If the configuration is past the vocabulary's own caps, which no
    /// admitted creation can have produced.
    #[must_use]
    pub fn address(&self, hasher: &dyn Hasher) -> ComponentAddr {
        let bytes = self
            .config_bytes()
            .expect("an admitted configuration encodes");
        component_address(hasher, self.package, config_hash(hasher, &bytes), self.salt)
    }

    /// Whether this record derives `address`.
    ///
    /// The whole of certificate admission: the address commits the
    /// package, the configuration leaf's bytes and the salt, so equality
    /// here is the verification and there is nothing else to consult. The
    /// question is total over every class — an address of any other one is
    /// an address no record derives.
    #[must_use]
    pub fn derives(&self, hasher: &dyn Hasher, address: impl Into<Address>) -> bool {
        let Ok(bytes) = self.config_bytes() else {
            return false;
        };
        component_address(hasher, self.package, config_hash(hasher, &bytes), self.salt)
            == address.into()
    }
}

/// A presented certificate that does not derive the address it claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("the presented record does not derive the address it claims")]
pub struct CertificateMismatch;

/// Addresses to the creation-fixed record each one derives.
///
/// A verified cache, not an authority: every entry was checked against
/// the address that keys it, so a lookup here answers the same question
/// recomputing the derivation would, at the cost of a map probe instead
/// of a hash.
///
/// Principals are not entries. A principal address commits auth material
/// rather than code, and the code serving every principal is
/// protocol-defined — so one record answers for all of them, and an
/// account needs nothing registered before it can be called.
#[derive(Clone, Debug, Default)]
pub struct InstanceRegistry {
    principal: Option<Arc<InstanceMeta>>,
    instances: BTreeMap<Address, Arc<InstanceMeta>>,
}

impl InstanceRegistry {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            principal: None,
            instances: BTreeMap::new(),
        }
    }

    /// Bind the package that serves every principal address.
    ///
    /// The protocol's own account blueprint, resolved by class rather
    /// than by certificate: a principal's address derives from a key, so
    /// there is no package hash in it to check a claim against.
    pub fn serve_principals(&mut self, package: PackageHash) {
        self.principal = Some(Arc::new(InstanceMeta {
            package,
            config: Vec::new(),
            salt: Hash32([0; 32]),
        }));
    }

    /// Admit a presented record for `address`, verifying that it derives
    /// it.
    ///
    /// # Errors
    ///
    /// [`CertificateMismatch`] when the record derives some other
    /// address — the refusal that replaces a lookup coming back empty.
    pub fn admit(
        &mut self,
        hasher: &dyn Hasher,
        address: impl Into<Address>,
        meta: InstanceMeta,
    ) -> Result<(), CertificateMismatch> {
        let address = address.into();
        if !meta.derives(hasher, address) {
            return Err(CertificateMismatch);
        }
        match self.instances.entry(address) {
            Entry::Vacant(slot) => {
                slot.insert(Arc::new(meta));
            }
            // Two records deriving one address is a hash collision; the
            // first stands either way.
            Entry::Occupied(stored) => {
                debug_assert_eq!(**stored.get(), meta, "one address, two records");
            }
        }
        Ok(())
    }

    /// Admit a record at the address it derives, and answer that address.
    ///
    /// What creation does: an instance's address is a function of its
    /// package, its configuration and its salt, so the creator computes
    /// it rather than choosing one and recording the association.
    ///
    /// # Panics
    ///
    /// If the configuration is past the vocabulary's own caps.
    pub fn create(&mut self, hasher: &dyn Hasher, meta: InstanceMeta) -> ComponentAddr {
        let address = meta.address(hasher);
        match self.instances.entry(address.address()) {
            Entry::Vacant(slot) => {
                slot.insert(Arc::new(meta));
            }
            Entry::Occupied(stored) => {
                debug_assert_eq!(**stored.get(), meta, "one address, two records");
            }
        }
        address
    }

    /// Look up the creation-fixed record serving a call target.
    ///
    /// Both classes a target can carry are answered here and nothing else
    /// arrives: a principal resolves to the protocol's account blueprint
    /// by its class alone, an instance to the record its address derives.
    #[must_use]
    pub fn get(&self, target: impl Into<CallTarget>) -> Option<&InstanceMeta> {
        match target.into() {
            CallTarget::Principal(_) => self.principal.as_deref(),
            CallTarget::Component(address) => {
                self.instances.get(&address.address()).map(AsRef::as_ref)
            }
        }
    }

    /// The shared handle to the record serving a call target — what this
    /// registry answers a
    /// [`ChainRecords`](crate::records::ChainRecords) lookup with.
    #[must_use]
    pub fn record(&self, target: impl Into<CallTarget>) -> Option<Arc<InstanceMeta>> {
        match target.into() {
            CallTarget::Principal(_) => self.principal.clone(),
            CallTarget::Component(address) => {
                self.instances.get(&address.address()).map(Arc::clone)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::from_slice;
    use hyperscale_vm_types::PrincipalAddr;

    use super::*;
    use crate::hash::TestHasher;

    #[test]
    fn a_record_is_admitted_only_at_the_address_it_derives() {
        let meta = InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: vec![Value::U64(7)],
            salt: Hash32([2; 32]),
        };
        let address = meta.address(&TestHasher);
        assert!(meta.derives(&TestHasher, address));

        let mut registry = InstanceRegistry::new();
        assert_eq!(registry.admit(&TestHasher, address, meta.clone()), Ok(()));
        assert_eq!(registry.get(address), Some(&meta));

        // Any other address is a claim the derivation refuses.
        let elsewhere = ComponentAddr::new([9; 31]);
        assert_eq!(
            registry.admit(&TestHasher, elsewhere, meta),
            Err(CertificateMismatch)
        );
        assert_eq!(registry.get(elsewhere), None);
    }

    #[test]
    fn a_false_package_claim_is_refused_by_verification() {
        let honest = InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: vec![],
            salt: Hash32([2; 32]),
        };
        let address = honest.address(&TestHasher);
        // The same instance, claimed to run somebody else's code. There
        // is no lookup to disagree with: the address commits the package,
        // so the claim would need a hash collision to stand.
        let forged = InstanceMeta {
            package: PackageHash(Hash32([0xFF; 32])),
            ..honest.clone()
        };
        assert!(!forged.derives(&TestHasher, address));
        let mut registry = InstanceRegistry::new();
        assert_eq!(
            registry.admit(&TestHasher, address, forged),
            Err(CertificateMismatch)
        );

        // And the configuration is committed on the same terms.
        let reconfigured = InstanceMeta {
            config: vec![Value::U64(1)],
            ..honest
        };
        assert!(!reconfigured.derives(&TestHasher, address));
    }

    #[test]
    fn every_principal_resolves_without_an_entry() {
        let package = PackageHash(Hash32([3; 32]));
        let mut registry = InstanceRegistry::new();
        assert_eq!(
            registry.get(PrincipalAddr::new([1; 31])),
            None,
            "until the protocol's blueprint is bound"
        );
        registry.serve_principals(package);
        // One record answers for every principal: an account's identity
        // is in its address, so there is nothing per-account to hold.
        for seed in [1u8, 2, 0xFF] {
            let principal = PrincipalAddr::new([seed; 31]);
            assert_eq!(registry.get(principal).map(|m| m.package), Some(package));
        }
        // A component still needs its record.
        assert_eq!(registry.get(ComponentAddr::new([1; 31])), None);
    }

    #[test]
    fn the_leaf_stores_the_record_the_address_commits() {
        let meta = InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: vec![Value::U64(7), Value::U128(9)],
            salt: Hash32([2; 32]),
        };
        // The address commits the configuration's own encoding.
        let bytes = meta.config_bytes().expect("the config encodes");
        assert_eq!(bytes, to_vec(&meta.config).unwrap());
        assert_eq!(
            meta.address(&TestHasher),
            component_address(
                &TestHasher,
                meta.package,
                config_hash(&TestHasher, &bytes),
                meta.salt,
            )
        );
        // The leaf stores the whole record, and the stored record is
        // self-verifying: decode it and it derives the address it sits
        // under.
        let leaf = meta.leaf_bytes().expect("the record encodes");
        let stored: InstanceMeta = from_slice(&leaf).expect("the leaf decodes");
        assert_eq!(stored, meta);
        assert!(stored.derives(&TestHasher, meta.address(&TestHasher)));
    }
}
