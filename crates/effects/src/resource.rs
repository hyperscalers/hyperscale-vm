//! The resource record: what an issuer declares about a resource.
//!
//! A resource address is pure derivation — provenance is the identity —
//! and this cell is what the identity points at: the resource's kind and
//! its display quantization, written by the issuer under its own prefix.
//! Minting and burning stay the issuer's own declared effects on vaults;
//! the record says what they issue, never how much of it exists.

use hyperscale_hbor::{DecodeError, EncodeError, Hbor, from_slice_with_depth, to_vec_with_depth};
use hyperscale_vm_types::{Address, CollectionId, ResourceAddr, SubstateKey};

use crate::dsl::{Expr, TargetExpr};
use crate::hash::Hasher;
use crate::types::{Value, child_key, collection_id, native_address, resource_address};
use crate::vocabulary::GENESIS_PUBLISHER;
pub use crate::vocabulary::{INSTANCE, NF_VAULT, RESOURCE};

/// What a resource is: divisible value, or named instances.
///
/// Derivation material before it is anything else: the discriminant is
/// folded into [`resource_address`](crate::types::resource_address), so
/// one address names one kind and a resource minted as both kinds is
/// two resources rather than a conflation. The same vocabulary types an
/// edge — declared, evaluated from the producing method's output
/// projection, and never sniffed from what crosses: the kind is what
/// admission binds a consumer's parameter against, and what a signed
/// bound is judged in the terms of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum ResourceKind {
    /// Divisible value: linear amounts in vault cells; edges carry
    /// 16-byte quantities.
    Fungible,
    /// Named instances held as sub-collection entries; edges carry id
    /// sets.
    NonFungible,
}

impl ResourceKind {
    /// The kind's derivation byte: the part [`resource_address`] folds
    /// between the minter and the material.
    ///
    /// [`resource_address`]: crate::types::resource_address
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Fungible => 0,
            Self::NonFungible => 1,
        }
    }
}

/// The resource `instance` issues under `mark` — the mark separating it
/// from the instance's other issues, an empty one naming the primary.
///
/// The one spelling of how a mark becomes derivation material. The
/// authoring surface reaches the same address by evaluating
/// `SelfResource` over the mark as a byte literal, and the routed grant
/// is lowered through this, so the two agree because they are one code
/// path pinned by one test.
#[must_use]
pub fn issued_resource(
    hasher: &dyn Hasher,
    instance: impl Into<Address>,
    kind: ResourceKind,
    mark: &[u8],
) -> ResourceAddr {
    let material = if mark.is_empty() {
        Vec::new()
    } else {
        vec![Value::Bytes(mark.to_vec()).canonical_bytes()]
    };
    resource_address(hasher, instance, kind, &material)
}

/// The decoder cap for a record cell: a flat two-field struct, one level
/// of body over the frame.
const RECORD_WIRE_DEPTH: usize = 4;

/// What a record states about its resource, in the shape a client reads.
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

impl Fungibility {
    /// The kind this record restates.
    ///
    /// Restates rather than states: the address already commits it, and
    /// the record carries it because a hash cannot be read backwards —
    /// a client learns a resource's kind here, never the kernel.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        match self {
            Self::Fungible { .. } => ResourceKind::Fungible,
            Self::NonFungible => ResourceKind::NonFungible,
        }
    }
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

/// The protocol's fee and transfer resource: the genesis publisher's
/// primary issue.
///
/// A resource like any other — the minter is the one address no signer
/// reaches, which is exactly the strength the fee resource needs: no
/// transaction can present a method of the publisher, so who may mint it
/// is nobody, by the same arithmetic that answers it for every resource.
/// Supply moves only where the protocol writes state directly.
#[must_use]
pub fn xrd(hasher: &dyn Hasher) -> ResourceAddr {
    let publisher = native_address(hasher, GENESIS_PUBLISHER);
    resource_address(hasher, publisher, ResourceKind::Fungible, &[])
}

/// The record cell for `resource` under `issuer`: the canonical child at
/// the `RESOURCE` slot, keyed by the resource's own address.
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
/// everything that consults holdings directly — a possession
/// condition's read, the linearity oracle's scan.
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

/// The declaring side's spelling of that same fold: the whole
/// `(NF_VAULT, resource)` interval under the declaring instance, at most
/// `cap` entries of it.
///
/// Every holdings declaration is this one shape — deposit and withdraw
/// range over it — so a declaration that spells the fold any other way
/// is refused rather than silently unmatched. The cap is ordinarily the
/// count of the ids the call itself names — `Len` over the argument or
/// the edge's id projection — so a move declares exactly the walk it
/// performs, and a full edge always fits the interval filing it by
/// construction.
#[must_use]
pub fn holdings_range(resource: Expr, cap: Expr) -> TargetExpr {
    TargetExpr::Range {
        owner: Expr::SelfAddr,
        collection: NF_VAULT,
        material: vec![resource],
        lo: Expr::Literal(Value::U128(0)),
        hi: Expr::Literal(Value::U128(u128::MAX)),
        cap,
    }
}

/// One entry of that same interval: the instance of `resource` this
/// holder keeps at `id`.
///
/// Minting an instance claim takes a `Holds { Present }` condition over
/// exactly this target, keyed by the same badge and id expressions the
/// mint names — which is what makes the instance verified and the
/// instance minted one thing. An entry is also the cheaper access: one
/// leaf rather than a scan the whole id space is declared over.
#[must_use]
pub fn holdings_entry(resource: Expr, id: Expr) -> TargetExpr {
    TargetExpr::Entry {
        owner: Expr::SelfAddr,
        collection: NF_VAULT,
        material: vec![resource],
        order: id,
    }
}

/// The data cell for one instance of `resource` under `issuer`, keyed by
/// the resource and the instance's id.
///
/// Under the issuer rather than the holder, so the cell never moves — a
/// transfer renames a holdings entry and touches no data.
///
/// A mint declares this leaf absent, so creating an instance and
/// overwriting one are different declarations and the shard holding the
/// leaf tells them apart before any body runs. What that buys is the
/// collision case: a fresh id is derived from the envelope and the
/// creating node's position, so two mints agreeing on one is not
/// something either sender can arrange, and the requirement is what
/// makes the unlucky one a refusal rather than a silent rewrite of an
/// instance somebody already holds.
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
    use hyperscale_vm_types::{Address, AddressClass};

    use super::{
        Fungibility, ResourceRecord, holdings_collection, instance_data_key, resource_record_key,
    };
    use crate::hash::TestHasher;
    use crate::types::native_address;
    use crate::vocabulary::GENESIS_PUBLISHER;

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
        let xrd = super::xrd(&TestHasher);
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
