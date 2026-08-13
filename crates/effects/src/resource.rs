//! The resource record: what an issuer declares about a resource.
//!
//! A resource address is pure derivation — provenance is the identity —
//! and this cell is what the identity points at: the resource's kind and
//! its display quantization, written by the issuer under its own prefix.
//! Minting and burning stay the issuer's own declared effects on vaults;
//! the record says what they issue, never how much of it exists.

use hyperscale_hbor::{DecodeError, EncodeError, Hbor, from_slice_with_depth, to_vec_with_depth};

use crate::hash::Hasher;
pub use crate::stdlib::{INSTANCE, NF_VAULT, RESOURCE};
use crate::types::{Address, CollectionId, SubstateKey, Value, child_key, collection_id};

/// The decoder cap for a record cell: a flat two-field struct, one level
/// of body over the frame.
const RECORD_WIRE_DEPTH: usize = 4;

/// What a resource is: divisible value, or named instances.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum Fungibility {
    /// Linear amounts in vault cells; edges carry 16-byte quantities.
    Fungible {
        /// Display quantization: how many base-10 subunit digits a
        /// client renders. Amounts are integers of the smallest unit
        /// everywhere in the kernel; nothing on-chain consults this.
        divisibility: u8,
    },
    /// Named instances held as sub-collection entries; edges carry id
    /// sets. Instances are whole by construction, so there is no
    /// divisibility to state.
    NonFungible,
}

/// One resource's record cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct ResourceRecord {
    /// The resource's kind. What discriminates an amount edge from an id
    /// edge, checked wherever a declaration types one.
    pub kind: Fungibility,
}

impl ResourceRecord {
    /// The record's canonical cell bytes.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] only on an encoder failure no well-formed record
    /// can reach; surfaced rather than swallowed so a future field's cap
    /// lands somewhere.
    pub fn to_cell(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec_with_depth(self, RECORD_WIRE_DEPTH)
    }

    /// One record from its canonical cell bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on trailing bytes or a non-canonical form.
    pub fn from_cell(bytes: &[u8]) -> Result<Self, DecodeError> {
        from_slice_with_depth(bytes, RECORD_WIRE_DEPTH)
    }
}

/// The record cell for `resource` under `issuer`: the canonical child at
/// the `RESOURCE` role, keyed by the resource's own address.
///
/// Computable by anyone who knows the issuer — which the resource's
/// derivation names — so reaching a record is level-one access like
/// reaching a vault, never a search.
#[must_use]
pub fn resource_record_key(
    hasher: &dyn Hasher,
    issuer: impl Into<Address>,
    resource: impl Into<Address>,
) -> SubstateKey {
    child_key(
        hasher,
        issuer,
        RESOURCE,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// The holdings sub-collection for `resource` under `holder`: the
/// `(NF_VAULT, resource)` fold whose entries, at the instance's id as
/// the order key, are the instances the holder has.
///
/// The declaring side spells the same fold as an entry target with the
/// resource as its collection material; this is that identity for
/// everything that consults holdings directly — the custody gate's
/// possession read, the linearity oracle's scan.
#[must_use]
pub fn holdings_collection(
    hasher: &dyn Hasher,
    holder: impl Into<Address>,
    resource: impl Into<Address>,
) -> CollectionId {
    collection_id(
        hasher,
        holder.into(),
        NF_VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// The data cell for one instance of `resource` under `issuer`, keyed by
/// the resource and the instance's id: written at mint, immutable after.
///
/// Under the issuer rather than the holder, so the cell never moves — a
/// transfer renames a holdings entry and touches no data.
#[must_use]
pub fn instance_data_key(
    hasher: &dyn Hasher,
    issuer: impl Into<Address>,
    resource: impl Into<Address>,
    id: u64,
) -> SubstateKey {
    child_key(
        hasher,
        issuer,
        INSTANCE,
        &[
            Value::Address(resource.into()).canonical_bytes(),
            Value::U64(id).canonical_bytes(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::assert_canonical;

    use super::{
        Fungibility, ResourceRecord, holdings_collection, instance_data_key, resource_record_key,
    };
    use crate::hash::TestHasher;
    use crate::stdlib::{GENESIS_PUBLISHER, XRD};
    use crate::types::{Address, AddressClass, native_address};

    #[test]
    fn records_round_trip_canonically() {
        for record in [
            ResourceRecord {
                kind: Fungibility::Fungible { divisibility: 18 },
            },
            ResourceRecord {
                kind: Fungibility::NonFungible,
            },
        ] {
            assert_canonical(&record);
            let bytes = record.to_cell().unwrap();
            assert_eq!(ResourceRecord::from_cell(&bytes).unwrap(), record);
        }
    }

    #[test]
    fn record_keys_separate_by_issuer_and_resource() {
        let publisher = native_address(&TestHasher, GENESIS_PUBLISHER);
        let xrd = native_address(&TestHasher, XRD);
        let other_issuer = Address::new([7; 31], AddressClass::Component);
        let other_resource = Address::new([8; 31], AddressClass::Resource);

        let key = resource_record_key(&TestHasher, publisher, xrd);
        assert_eq!(key.owner, publisher.address(), "records live at the issuer");
        assert_ne!(
            key,
            resource_record_key(&TestHasher, other_issuer, xrd),
            "another issuer is another cell"
        );
        assert_ne!(
            key,
            resource_record_key(&TestHasher, publisher, other_resource),
            "another resource is another cell"
        );
    }

    #[test]
    fn holdings_collections_separate_by_holder_and_resource() {
        let holder = Address::new([1; 31], AddressClass::Component);
        let other_holder = Address::new([2; 31], AddressClass::Component);
        let resource = Address::new([3; 31], AddressClass::Resource);
        let other_resource = Address::new([4; 31], AddressClass::Resource);

        let collection = holdings_collection(&TestHasher, holder, resource);
        assert_eq!(
            collection,
            holdings_collection(&TestHasher, holder, resource),
            "the fold is a pure derivation"
        );
        assert_ne!(
            collection,
            holdings_collection(&TestHasher, other_holder, resource),
            "another holder holds elsewhere"
        );
        assert_ne!(
            collection,
            holdings_collection(&TestHasher, holder, other_resource),
            "another resource is another sub-collection"
        );
    }

    #[test]
    fn instance_data_keys_separate_by_resource_and_id() {
        let issuer = Address::new([1; 31], AddressClass::Component);
        let resource = Address::new([3; 31], AddressClass::Resource);
        let other_resource = Address::new([4; 31], AddressClass::Resource);

        let key = instance_data_key(&TestHasher, issuer, resource, 7);
        assert_eq!(key.owner, issuer, "instance data lives at the issuer");
        assert_ne!(
            key,
            instance_data_key(&TestHasher, issuer, resource, 8),
            "another instance is another cell"
        );
        assert_ne!(
            key,
            instance_data_key(&TestHasher, issuer, other_resource, 7),
            "another resource is another cell"
        );
    }
}
