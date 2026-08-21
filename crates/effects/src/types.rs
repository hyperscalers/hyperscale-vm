//! Keys, values, modes, and effect targets — the vocabulary shared by the
//! DSL evaluator, the router, and the kernel.

use hyperscale_hbor::{Hbor, to_vec};
use hyperscale_vm_types::{
    Address, CollectionId, ComponentAddr, LocalKey, NativeAddr, PackageAddr, PrincipalAddr,
    ResourceAddr, SchemeId, SubstateKey,
};

use crate::hash::{Hash32, Hasher};
use crate::metadata::PackageHash;
use crate::resource::{ResourceGrants, ResourceKind};

/// A shard identity, as resolved from an address prefix.
///
/// Opaque here: this crate reads it only as a routing key, and what it
/// means belongs to whoever implements [`ShardResolver`](crate::route::ShardResolver).
///
/// Wide enough for a trie leaf, which is what the embedder's shards are.
/// A leaf identified by `(depth, path)` flattens to the heap index
/// `(1 << depth) | path`, and a depth bound of 63 puts that at the top of
/// `u64`. Narrower would not merely truncate: two leaves at different
/// depths would collide on one id, and a shard would silently be credited
/// with another's effects. A cap on the number of *live* shards does not
/// bound their depth — an unbalanced trie reaches past a narrow id with
/// far fewer leaves than the cap allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId(pub u64);

/// A tag naming a kernel-addressed slot under an owner.
///
/// The slot says which child — a vault, a claims cell, a field group, an
/// ordered collection — a canonical address refers to. The word is a
/// storage one and nothing else: authority is [`RoleId`] and its role
/// set, and the two share no vocabulary.
///
/// A slot is hashed with its owner, and an owner belongs to one package,
/// so two packages naming one value never collide: a slot is scoped by
/// the address it sits under, not by this space. What the space
/// partitions is the three populations that *do* share an owner:
///
/// - the kernel's own, at the top ([`NULLIFIER_SLOT`], [`PACKAGE_SLOT`]),
///   reached by the kernel and the publish path and by nothing else;
/// - the protocol vocabulary, counting up from one — the cells an engine
///   derives keys for without consulting any metadata, so their values
///   are protocol facts rather than one package's business;
/// - a package's own, from [`PACKAGE_SLOT_BASE`] up, declared beside the
///   package that stores them.
///
/// A package's instances hold protocol-vocabulary cells under the same
/// address as their own, which is the whole reason the third band has to
/// clear the second. It never has to clear another package's.
///
/// [`RoleId`]: crate::RoleId
/// [`NULLIFIER_SLOT`]: crate::NULLIFIER_SLOT
/// [`PACKAGE_SLOT`]: crate::PACKAGE_SLOT
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct SlotId(pub u16);

/// The first slot a package may use for state of its own.
///
/// Above the protocol vocabulary with room left over, so a cell added to
/// that vocabulary later is not a renumbering of every package that ever
/// stored anything.
pub const PACKAGE_SLOT_BASE: u16 = 16;

/// The first slot the kernel keeps for itself.
///
/// The top of the space, as the bottom is the protocol vocabulary's and
/// the middle is where packages number from. The cells here are reached
/// by the publish path and by the envelope, under a publisher's and a
/// signer's prefix, and no signature declares one — which is what makes
/// the band a refusal rather than a shape.
pub const KERNEL_SLOT_BASE: u16 = 0xFFFE;

// The three bands in order, held at compile time: all three are
// constants, so a base that swallowed the band below it is a thing the
// build can refuse outright.
const _: () = assert!(KERNEL_SLOT_BASE > PACKAGE_SLOT_BASE);

/// A package's `n`th own slot.
///
/// Packages number from zero independently, a value being scoped by the
/// owner it is hashed with. A package authored through `#[blueprint]`
/// gets the absolute slot from the macro, which numbers its state in
/// declaration order; this is the same arithmetic for a declaration
/// written by hand.
#[must_use]
pub const fn package_slot(n: u16) -> SlotId {
    SlotId(PACKAGE_SLOT_BASE + n)
}

/// A protocol-defined role a native address names.
///
/// The register is closed and fail-closed like the class tags: a value is
/// assigned or it is not an address, and adding one is a protocol version
/// change. Where a class tag is wire-visible and a slot is internal to
/// a derivation, both are halves of one namespace policy.
///
/// A number is derivation material — the address is a hash over it — so
/// it names one role for as long as the protocol runs and is never
/// reassigned. The sequence has gaps for that reason, and a gap is not a
/// free number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct NativeRole(pub u16);

const DOMAIN_CHILD: &[u8] = b"hyperscale-vm/child-key";
const DOMAIN_COLLECTION: &[u8] = b"hyperscale-vm/collection-id";
const DOMAIN_ORDER: &[u8] = b"hyperscale-vm/order-key";
const DOMAIN_PRINCIPAL: &[u8] = b"hyperscale-vm/principal-address";
const DOMAIN_COMPONENT: &[u8] = b"hyperscale-vm/component-address";
const DOMAIN_PACKAGE_ADDRESS: &[u8] = b"hyperscale-vm/package-address";
const DOMAIN_RESOURCE: &[u8] = b"hyperscale-vm/resource-address";
const DOMAIN_NATIVE: &[u8] = b"hyperscale-vm/native-address";
const DOMAIN_INSTANCE_CONFIG: &[u8] = b"hyperscale-vm/instance-config";

/// The canonical child key for slot-bound state under `owner`.
///
/// The local half is the hash of the owner, the slot, and the material,
/// truncated to 16 bytes — which is what makes level-one access ("the vault
/// for resource R under account A") pure computation, never a state read.
///
/// Sixteen bytes is a deliberate choice, not a leftover: it puts the local
/// half at a 64-bit birthday bound against collisions. The owner salted
/// into the digest is what keeps that domain per-owner — material can be
/// chosen by a third party (an attacker-minted resource names a vault
/// local), and without the salt one ground collision would reproduce under
/// every owner at once. The leaf key is the owner prefix plus this half,
/// so a collision cannot cross a prefix and cannot cross a shard.
#[must_use]
pub fn child_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    slot: SlotId,
    material: &[Vec<u8>],
) -> SubstateKey {
    let owner = owner.into();
    let owner_bytes = owner.to_bytes();
    let slot_bytes = slot.0.to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + material.len());
    parts.push(&owner_bytes);
    parts.push(&slot_bytes);
    parts.extend(material.iter().map(Vec::as_slice));
    let digest = hasher.hash(DOMAIN_CHILD, &parts);
    let mut local = [0u8; 16];
    local.copy_from_slice(&digest.0[..16]);
    SubstateKey {
        owner,
        local: LocalKey(local),
    }
}

/// The collection identity for `slot` and `material` under `owner`.
///
/// Sixteen bytes and owner-salted for the same reasons as [`child_key`]:
/// the truncation sits at a 64-bit birthday bound, material can be chosen
/// by a third party, and the salt confines a ground collision to the one
/// owner it could hurt. Domain-separated from child keys, so a collection
/// identity never aliases a point cell's local half.
#[must_use]
pub fn collection_id(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    slot: SlotId,
    material: &[Vec<u8>],
) -> CollectionId {
    let owner_bytes = owner.into().to_bytes();
    let slot_bytes = slot.0.to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + material.len());
    parts.push(&owner_bytes);
    parts.push(&slot_bytes);
    parts.extend(material.iter().map(Vec::as_slice));
    let digest = hasher.hash(DOMAIN_COLLECTION, &parts);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest.0[..16]);
    CollectionId(id)
}

/// The order key for `material` in the collection at `slot` under `owner`
/// — where a hashed key lands in a collection's order space.
///
/// This is what makes a collection *unordered*: hashing the logical key
/// gives it an arbitrary-but-canonical position, so point access stays
/// pure computation and a capped range walks the entries in an order
/// nobody chose. Owner-and-slot-salted and truncated to sixteen bytes for
/// the same reasons as [`collection_id`], and domain-separated from it, so
/// a key's position never aliases a collection's identity.
#[must_use]
pub fn order_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    slot: SlotId,
    material: &[Vec<u8>],
) -> u128 {
    let owner_bytes = owner.into().to_bytes();
    let slot_bytes = slot.0.to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + material.len());
    parts.push(&owner_bytes);
    parts.push(&slot_bytes);
    parts.extend(material.iter().map(Vec::as_slice));
    let digest = hasher.hash(DOMAIN_ORDER, &parts);
    let mut order = [0u8; 16];
    order.copy_from_slice(&digest.0[..16]);
    u128::from_be_bytes(order)
}

/// An address body: the leading 31 bytes of `digest`.
fn body(digest: Hash32) -> [u8; 31] {
    let mut body = [0u8; 31];
    body.copy_from_slice(&digest.0[..31]);
    body
}

/// The principal address a public key opens.
///
/// The address commits to the auth material itself, so verifying that a
/// signer may act as a target is a pure function of the envelope: the key
/// hashes to the address body, and the signature verifies against the
/// key. No registration, and nothing to look up.
///
/// The scheme is in the preimage because a principal is scheme-bound
/// forever — the same key under a second scheme is a second principal,
/// which is what keeps a scheme added later from landing on an address
/// already in use.
#[must_use]
pub fn principal_address(
    hasher: &dyn Hasher,
    scheme: SchemeId,
    public_key: &[u8],
) -> PrincipalAddr {
    let scheme_bytes = scheme.0.to_le_bytes();
    PrincipalAddr::new(body(
        hasher.hash(DOMAIN_PRINCIPAL, &[&scheme_bytes, public_key]),
    ))
}

/// The address of the instance `package` creates under `config`, salted by
/// the fresh id of the transaction that created it.
///
/// The blueprint and the creation-fixed configuration are both welded in:
/// an instance's address is a commitment to the code it runs and to the
/// values its effect signatures evaluate over, and neither can move
/// without the address moving. So an "upgrade" can only be a new address,
/// and dynamic dispatch through state stays inexpressible at the
/// addressing layer as well as in the effect model.
///
/// The salt is what separates two instances created from one package
/// under one configuration.
#[must_use]
pub fn component_address(
    hasher: &dyn Hasher,
    package: PackageHash,
    config: Hash32,
    salt: Hash32,
) -> ComponentAddr {
    ComponentAddr::new(body(
        hasher.hash(DOMAIN_COMPONENT, &[&package.0.0, &config.0, &salt.0]),
    ))
}

/// The address of published code.
///
/// Content-addressed through its own domain, so the address is a function
/// of the artifact and of nothing else — the same code published twice is
/// the same address, and the binding holds for as long as the package
/// exists.
#[must_use]
pub fn package_address(hasher: &dyn Hasher, package: PackageHash) -> PackageAddr {
    PackageAddr::new(body(hasher.hash(DOMAIN_PACKAGE_ADDRESS, &[&package.0.0])))
}

/// The address of a resource minted under `minter`, sealing nothing.
///
/// A resource address commits to its provenance, its kind, and its
/// granted rules: who may mint it, what it is, and the behaviours it
/// grants are readable from the address, so a holder checks all three
/// by recomputing the derivation rather than by trusting a claim about
/// any of them. The material separates the resources one minter issues;
/// this spelling commits the empty granted set, which is what almost
/// every resource carries.
#[must_use]
pub fn resource_address(
    hasher: &dyn Hasher,
    minter: impl Into<Address>,
    kind: ResourceKind,
    material: &[Vec<u8>],
) -> ResourceAddr {
    granting_resource_address(hasher, minter, kind, &ResourceGrants::new(), material)
}

/// The address of a resource minted under `minter`, sealing `rules`.
///
/// The empty set is committed like any other — a granting resource and an
/// one granting nothing can never collide — and immutability is the derivation:
/// a rule that changed would be a different resource.
#[must_use]
pub fn granting_resource_address(
    hasher: &dyn Hasher,
    minter: impl Into<Address>,
    kind: ResourceKind,
    rules: &ResourceGrants,
    material: &[Vec<u8>],
) -> ResourceAddr {
    let minter_bytes = minter.into().to_bytes();
    let kind_tag = [kind.tag()];
    let commitment = rules.commitment(hasher);
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + material.len());
    parts.push(&minter_bytes);
    parts.push(&kind_tag);
    parts.push(&commitment.0);
    parts.extend(material.iter().map(Vec::as_slice));
    ResourceAddr::new(body(hasher.hash(DOMAIN_RESOURCE, &parts)))
}

/// The address of a protocol role.
///
/// Derived rather than picked, so a well-known address is uniformly
/// distributed across the prefix space like every other and lands on no
/// shard by preference. What the address names is the role; the code
/// behind it moves with the protocol version.
#[must_use]
pub fn native_address(hasher: &dyn Hasher, role: NativeRole) -> NativeAddr {
    let role_bytes = role.0.to_le_bytes();
    NativeAddr::new(body(hasher.hash(DOMAIN_NATIVE, &[&role_bytes])))
}

/// The commitment an instance's address carries to its creation-fixed
/// configuration.
///
/// The preimage is the encoded configuration leaf verbatim — one framed
/// part — so a record and the state it describes agree by literal
/// byte equality, with the decoder's canonicity supplying the bijection
/// between the value list and its bytes.
#[must_use]
pub fn config_hash(hasher: &dyn Hasher, config_leaf: &[u8]) -> Hash32 {
    hasher.hash(DOMAIN_INSTANCE_CONFIG, &[config_leaf])
}

/// The bound on a value's nesting depth. A recursion bound.
///
/// Admission rejects a deeper literal before it reaches the manifest hash.
/// A wire decoder is expected to bound nesting too — a value deep enough
/// to exhaust the native stack in `Clone` or `Drop` never reaches this
/// crate — and this bound is what makes a decoder that does not agree a
/// deterministic rejection rather than a divergence.
pub const MAX_VALUE_DEPTH: usize = 16;

/// The codec nesting cost of the deepest admissible value.
///
/// One value level costs at most two codec levels — the variant's
/// collection field and its hoisted element body — and adding a level
/// costs at least one more than a scalar leaf, so `2 * MAX_VALUE_DEPTH`
/// covers every value of admissible depth and no deeper one. The relation
/// is pinned by test at both boundaries, and it is what
/// [`Value::canonical_bytes`]' totality stands on: an admissible value
/// costs at most this many encoder levels, well under the default cap, so
/// hashing one cannot fail. No wire decoder passes this cap on its own —
/// values arrive inside larger structures under the default cap, and
/// `check_value_depth` gates admissible depth semantically at admission.
pub const MAX_VALUE_WIRE_DEPTH: usize = 2 * MAX_VALUE_DEPTH;

/// A typed value the DSL evaluates over: manifest literals, edge
/// projections, instance configuration fields, and everything derivable
/// from them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Value {
    /// An unsigned 64-bit integer.
    U64(u64),
    /// An unsigned 128-bit integer — the amount width.
    U128(u128),
    /// Opaque bytes.
    Bytes(Vec<u8>),
    /// A global object's address.
    Address(Address),
    /// A full substate key.
    Key(SubstateKey),
    /// The routable projection of a value edge: its static resource type
    /// and what it carries besides.
    Bucket {
        /// The resource the edge carries.
        resource: ResourceAddr,
        /// What crosses the edge: a dynamic amount, or named instances.
        content: EdgeContent,
    },
    /// A fixed-arity product.
    Tuple(Vec<Self>),
    /// A bounded homogeneous sequence.
    List(Vec<Self>),
    /// A judgment: what a predicate evaluates to.
    ///
    /// The one kind with no guest representation, and nothing hands one
    /// to an export: what crosses from a selection is the value the
    /// declaration chose, never the condition it chose by. Where a body
    /// needs the comparison itself, the operands cross and it is rebuilt
    /// there — so a boolean is never two copies agreeing by convention,
    /// because there is only ever the one.
    Bool(bool),
}

impl Value {
    /// The value's kind name, for diagnostics.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::U64(_) => "u64",
            Self::U128(_) => "u128",
            Self::Bytes(_) => "bytes",
            Self::Address(_) => "address",
            Self::Key(_) => "key",
            Self::Bucket { .. } => "bucket",
            Self::Tuple(_) => "tuple",
            Self::List(_) => "list",
            Self::Bool(_) => "bool",
        }
    }

    /// A canonical, unambiguous byte form: the hashing feed for
    /// child-address material and manifest identity — the value's HBOR
    /// encoding, so the hashed form and the wire form are one byte string.
    ///
    /// Total for every value the protocol hashes: [`check_value_depth`]
    /// gates admission before any hash is taken, an admissible value costs
    /// at most [`MAX_VALUE_WIRE_DEPTH`] encoder levels, and the default
    /// encoder cap leaves that margin twice over. A value nested past the
    /// cap fails to encode deterministically; the panic here names the
    /// broken precondition instead of hashing bytes no decoder would admit.
    ///
    /// # Panics
    ///
    /// On a value nested past the encoder's cap — a value no admission
    /// path can have admitted.
    ///
    /// [`check_value_depth`]: crate::admission
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        to_vec(self).expect("hashed values pass the depth gate first")
    }

    /// The value's nesting depth: a scalar is one, a tuple or list one more
    /// than its deepest element. Measured over an explicit stack, for the
    /// same reason the encoding is.
    #[must_use]
    pub fn depth(&self) -> usize {
        let mut deepest = 0;
        let mut stack: Vec<(&Self, usize)> = vec![(self, 1)];
        while let Some((value, depth)) = stack.pop() {
            deepest = deepest.max(depth);
            if let Self::Tuple(values) | Self::List(values) = value {
                stack.extend(values.iter().map(|child| (child, depth + 1)));
            }
        }
        deepest
    }
}

/// The bound on the instance ids one non-fungible edge may move — the
/// cap every id-carrying projection decodes under, and the count the
/// edge's boundary cell crossing is sized by.
///
/// A wire bound, not a price: the work of moving the ids is charged as
/// depth on the holdings interval they move through, whose cap is the
/// count of the ids themselves — so a full edge fits the interval
/// filing it by construction, at this bound or any other.
pub const MAX_IDS_PER_EDGE: usize = 64;

/// What a value edge carries besides its resource. Structural rather
/// than inferred, so a fungible edge cannot pose as an empty id set and
/// an id read on one refuses instead of answering nothing.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum EdgeContent {
    /// A dynamic amount, never visible to the DSL.
    Fungible,
    /// The named instances the edge moves — signed manifest content,
    /// which is what lets an effect signature declare per-id accesses.
    NonFungible {
        /// The instance ids, in the resource's id space.
        #[hbor(max = MAX_IDS_PER_EDGE)]
        ids: Vec<u64>,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_hbor::{assert_canonical, from_slice_with_depth};
    use hyperscale_vm_types::{AddressClass, ComponentAddr, ResourceAddr};

    use super::{
        Address, EdgeContent, LocalKey, MAX_VALUE_DEPTH, MAX_VALUE_WIRE_DEPTH, NativeRole,
        SchemeId, SlotId, SubstateKey, Value, child_key, component_address, config_hash,
        granting_resource_address, native_address, package_address, principal_address,
        resource_address, to_vec,
    };
    use crate::auth::RoleBytes;
    use crate::hash::{Hash32, TestHasher};
    use crate::metadata::PackageHash;
    use crate::presented::Presented;
    use crate::resource::{GrantedBehaviour, ResourceGrants, ResourceKind};
    use crate::rule::StoredRule;
    use crate::vectors::{
        CONFIG_LEAF, PACKAGE, SALT, address_vector_lines, address_vectors, expected_classes,
    };

    /// The hashing feed and the wire form are one byte string, and the
    /// vocabulary is canonical on the same terms as any wire type.
    #[test]
    fn canonical_bytes_is_the_wire_encoding() {
        let value = Value::Tuple(vec![
            Value::U64(1),
            Value::List(vec![Value::U64(2)]),
            Value::Bytes(vec![3, 4]),
            Value::Key(SubstateKey {
                owner: Address::new([5; 31], AddressClass::Component),
                local: LocalKey([6; 16]),
            }),
        ]);
        assert_eq!(value.canonical_bytes(), to_vec(&value).unwrap());
        assert_canonical(&value);
        assert_canonical(&Value::Bucket {
            resource: ResourceAddr::new([7; 31]),
            content: EdgeContent::Fungible,
        });
        assert_canonical(&Value::Bucket {
            resource: ResourceAddr::new([7; 31]),
            content: EdgeContent::NonFungible { ids: vec![3, 9] },
        });
    }

    /// The wire cap admits exactly the admissible depths, at both
    /// boundaries and for the widest leaf: one value level costs at most
    /// two decoder levels, so the relation is a constant, not a heuristic.
    #[test]
    fn the_wire_depth_cap_matches_the_value_depth_gate() {
        let nest = |mut value: Value, levels: usize| {
            for _ in 0..levels {
                value = Value::Tuple(vec![value]);
            }
            value
        };

        // Depth MAX with the costliest leaf decodes at the wire cap.
        let widest = nest(Value::Bytes(vec![1]), MAX_VALUE_DEPTH - 1);
        assert_eq!(widest.depth(), MAX_VALUE_DEPTH);
        let bytes = to_vec(&widest).unwrap();
        assert!(from_slice_with_depth::<Value>(&bytes, MAX_VALUE_WIRE_DEPTH).is_ok());

        // Depth MAX + 1 with the cheapest leaf does not.
        let deeper = nest(Value::U64(1), MAX_VALUE_DEPTH);
        assert_eq!(deeper.depth(), MAX_VALUE_DEPTH + 1);
        let bytes = to_vec(&deeper).unwrap();
        assert!(from_slice_with_depth::<Value>(&bytes, MAX_VALUE_WIRE_DEPTH).is_err());

        // A value past the encoder's own cap refuses to encode
        // deterministically instead of exhausting the native stack.
        let unhashable = nest(Value::U64(1), 70);
        assert!(to_vec(&unhashable).is_err());
    }

    #[test]
    fn child_keys_separate_by_slot_and_material() {
        let owner = Address::new([1; 31], AddressClass::Component);
        let a = child_key(&TestHasher, owner, SlotId(1), &[vec![9]]);
        assert_eq!(a, child_key(&TestHasher, owner, SlotId(1), &[vec![9]]));
        assert_ne!(a, child_key(&TestHasher, owner, SlotId(2), &[vec![9]]));
        assert_ne!(a, child_key(&TestHasher, owner, SlotId(1), &[vec![8]]));
        assert_ne!(a, child_key(&TestHasher, owner, SlotId(1), &[]));
        assert_eq!(a.owner, owner);
    }

    #[test]
    fn child_key_locals_separate_by_owner() {
        let a = child_key(
            &TestHasher,
            Address::new([1; 31], AddressClass::Component),
            SlotId(1),
            &[vec![9]],
        );
        let b = child_key(
            &TestHasher,
            Address::new([2; 31], AddressClass::Component),
            SlotId(1),
            &[vec![9]],
        );
        assert_ne!(a.local, b.local);
    }

    #[test]
    fn every_derivation_carries_its_own_class() {
        let derived = address_vectors(&TestHasher);
        let expected = expected_classes();
        assert_eq!(derived.len(), expected.len());
        for ((name, address), (expected_name, class)) in derived.iter().zip(expected) {
            assert_eq!(*name, expected_name);
            assert_eq!(address.class(), class, "{name}");
        }
    }

    #[test]
    fn derivation_vectors_are_pinned() {
        assert_eq!(
            address_vector_lines(&TestHasher),
            vec![
                "principal/ed25519/a = b0aa5269c8dbc00c682fcd9843f9d6e55f62e68f8add00221ac2c5f54df4d801",
                "principal/ed25519/b = ca6f00440ae6880825310430406d4bfc462131d3fa34aa0d993da698a6bd6e01",
                "component/salted = 182371a0c66262beab502fc6f5e9c7a92f94c5f903e378fdc07d999c58fa2b02",
                "package/content = 94cb538bce2c0a6cf61a9fff32d805fb229e1db7174679c17d404686430e4103",
                "resource/minted = 35e2ddac0061bd4baedfd4c17865b7fdb9c43ff09bcdc667577a354a98e7a104",
                "resource/minted-nf = ce323aed0de4701b5e19461095919d188c93222c950ac229058846d5fe9c3604",
                "native/genesis-publisher = dca99635de8cbff5c1f6b5fccaaa14489bdf24ac9f2b1be31e576da9a31c5305",
                "resource/xrd = d683b9db3acf0dc13756bad11d8011cc5d6eacd723a678b5b44f6707d5a56404",
            ]
        );
    }

    #[test]
    fn a_principal_is_bound_to_its_scheme() {
        let key = [7u8; 32];
        let under_one = principal_address(&TestHasher, SchemeId::ED25519, &key);
        assert_eq!(
            under_one,
            principal_address(&TestHasher, SchemeId::ED25519, &key)
        );
        // A scheme added later must not land on an address already in
        // use: the same key under a second scheme is a second principal.
        assert_ne!(under_one, principal_address(&TestHasher, SchemeId(2), &key));
        assert_ne!(
            under_one,
            principal_address(&TestHasher, SchemeId::ED25519, &[8u8; 32])
        );
    }

    #[test]
    fn a_component_commits_to_its_package_config_and_salt() {
        let config = config_hash(&TestHasher, CONFIG_LEAF);
        let base = component_address(&TestHasher, PACKAGE, config, SALT);
        assert_eq!(base, component_address(&TestHasher, PACKAGE, config, SALT));

        let other_package = PackageHash(Hash32([0x71; 32]));
        assert_ne!(
            base,
            component_address(&TestHasher, other_package, config, SALT)
        );
        assert_ne!(
            base,
            component_address(
                &TestHasher,
                PACKAGE,
                config_hash(&TestHasher, b"a different configuration"),
                SALT
            )
        );
        assert_ne!(
            base,
            component_address(&TestHasher, PACKAGE, config, Hash32([0x5b; 32]))
        );
    }

    #[test]
    fn a_resource_separates_by_minter_kind_and_material() {
        let fungible = ResourceKind::Fungible;
        let config = config_hash(&TestHasher, CONFIG_LEAF);
        let minter = component_address(&TestHasher, PACKAGE, config, SALT);
        let other = component_address(&TestHasher, PACKAGE, config, Hash32([0x5c; 32]));
        let base = resource_address(&TestHasher, minter, fungible, &[b"unit".to_vec()]);

        assert_eq!(
            base,
            resource_address(&TestHasher, minter, fungible, &[b"unit".to_vec()])
        );
        assert_ne!(
            base,
            resource_address(&TestHasher, other, fungible, &[b"unit".to_vec()])
        );
        assert_ne!(
            base,
            resource_address(&TestHasher, minter, fungible, &[b"other".to_vec()])
        );
        // The kind is derivation material, so a resource minted as both
        // kinds is two addresses rather than one address worn two ways.
        assert_ne!(
            base,
            resource_address(
                &TestHasher,
                minter,
                ResourceKind::NonFungible,
                &[b"unit".to_vec()]
            )
        );
        // The minter is a framed part, so material cannot be chosen to
        // reproduce another minter's resource by shifting the boundary.
        assert_ne!(
            resource_address(
                &TestHasher,
                minter,
                fungible,
                &[b"ab".to_vec(), b"c".to_vec()]
            ),
            resource_address(&TestHasher, minter, fungible, &[b"abc".to_vec()])
        );
        // The granted rules are derivation material too: a rule cannot
        // change without the resource becoming a different resource, and
        // sealing nothing is committed like sealing something.
        let admit = |who: ComponentAddr| {
            let mut rules = ResourceGrants::new();
            rules.set(
                GrantedBehaviour::Recall,
                RoleBytes::try_from(&StoredRule::Require(Presented::Identity(who.into())))
                    .expect("a rule encodes"),
            );
            rules
        };
        let granting =
            granting_resource_address(&TestHasher, minter, fungible, &admit(minter), &[]);
        assert_ne!(
            granting,
            resource_address(&TestHasher, minter, fungible, &[])
        );
        assert_ne!(
            granting,
            granting_resource_address(&TestHasher, minter, fungible, &admit(other), &[])
        );
    }

    #[test]
    fn the_class_domains_do_not_share_a_preimage() {
        // Each derivation hashes under its own domain, so no two classes
        // can be made to agree on a body by feeding them equal material.
        let package = PackageHash(Hash32([0x11; 32]));
        let bodies = [
            principal_address(&TestHasher, SchemeId(0x11), &[0x11; 32]).body(),
            component_address(&TestHasher, package, Hash32([0x11; 32]), Hash32([0x11; 32])).body(),
            package_address(&TestHasher, package).body(),
            resource_address(
                &TestHasher,
                Address::new([0x11; 31], AddressClass::Component),
                ResourceKind::Fungible,
                &[vec![0x11; 32]],
            )
            .body(),
            native_address(&TestHasher, NativeRole(0x11)).body(),
        ];
        let unique: BTreeSet<[u8; 31]> = bodies.iter().copied().collect();
        assert_eq!(unique.len(), bodies.len());
    }
}
