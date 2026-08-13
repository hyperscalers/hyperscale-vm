//! Keys, values, modes, and effect targets — the vocabulary shared by the
//! DSL evaluator, the router, and the kernel.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Hbor, to_vec};
pub use hyperscale_vm_types::{
    Address, AddressClass, CallTarget, CollectionId, ComponentAddr, InvalidAddress, LocalKey, Mode,
    ModeKind, NativeAddr, NetworkWord, NotAResource, NotCallable, PackageAddr, PrincipalAddr,
    ResourceAddr, ResourceRef, SchemeId, SubstateKey, TextError, WrongClass, compatible,
};

use crate::hash::{Hash32, Hasher};
use crate::metadata::PackageHash;

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

/// A role tag naming a kernel-addressed slot under an owner.
///
/// The role says which child — a vault, a claims cell, a field group, an
/// ordered collection — a canonical address refers to. Role values are
/// package conventions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct RoleId(pub u16);

/// A protocol-defined role a native address names.
///
/// The register is closed and fail-closed like the class tags: a value is
/// assigned or it is not an address, and adding one is a protocol version
/// change. Where a class tag is wire-visible and a role id is internal to
/// a derivation, both are halves of one namespace policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct NativeRole(pub u16);

const DOMAIN_CHILD: &[u8] = b"hyperscale-vm/child-key";
const DOMAIN_COLLECTION: &[u8] = b"hyperscale-vm/collection-id";
const DOMAIN_ORDER: &[u8] = b"hyperscale-vm/order-key";
const DOMAIN_PRINCIPAL: &[u8] = b"hyperscale-vm/principal-address";
const DOMAIN_COMPONENT: &[u8] = b"hyperscale-vm/component-address";
const DOMAIN_PACKAGE: &[u8] = b"hyperscale-vm/package-address";
const DOMAIN_RESOURCE: &[u8] = b"hyperscale-vm/resource-address";
const DOMAIN_NATIVE: &[u8] = b"hyperscale-vm/native-address";
const DOMAIN_INSTANCE_CONFIG: &[u8] = b"hyperscale-vm/instance-config";

/// The canonical child key for role-bound state under `owner`.
///
/// The local half is the hash of the owner, the role, and the material,
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
    role: RoleId,
    material: &[Vec<u8>],
) -> SubstateKey {
    let owner = owner.into();
    let owner_bytes = owner.to_bytes();
    let role_bytes = role.0.to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + material.len());
    parts.push(&owner_bytes);
    parts.push(&role_bytes);
    parts.extend(material.iter().map(Vec::as_slice));
    let digest = hasher.hash(DOMAIN_CHILD, &parts);
    let mut local = [0u8; 16];
    local.copy_from_slice(&digest.0[..16]);
    SubstateKey {
        owner,
        local: LocalKey(local),
    }
}

/// The collection identity for `role` and `material` under `owner`.
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
    role: RoleId,
    material: &[Vec<u8>],
) -> CollectionId {
    let owner_bytes = owner.into().to_bytes();
    let role_bytes = role.0.to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + material.len());
    parts.push(&owner_bytes);
    parts.push(&role_bytes);
    parts.extend(material.iter().map(Vec::as_slice));
    let digest = hasher.hash(DOMAIN_COLLECTION, &parts);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest.0[..16]);
    CollectionId(id)
}

/// The order key for `material` in the collection at `role` under `owner`
/// — where a hashed key lands in a collection's order space.
///
/// This is what makes a collection *unordered*: hashing the logical key
/// gives it an arbitrary-but-canonical position, so point access stays
/// pure computation and a capped range walks the entries in an order
/// nobody chose. Owner-and-role-salted and truncated to sixteen bytes for
/// the same reasons as [`collection_id`], and domain-separated from it, so
/// a key's position never aliases a collection's identity.
#[must_use]
pub fn order_key(
    hasher: &dyn Hasher,
    owner: impl Into<Address>,
    role: RoleId,
    material: &[Vec<u8>],
) -> u128 {
    let owner_bytes = owner.into().to_bytes();
    let role_bytes = role.0.to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + material.len());
    parts.push(&owner_bytes);
    parts.push(&role_bytes);
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
    PackageAddr::new(body(hasher.hash(DOMAIN_PACKAGE, &[&package.0.0])))
}

/// The address of a resource minted under `minter`.
///
/// A resource address commits to its provenance: who may mint it is
/// readable from the address, so a holder checks supply authority by
/// recomputing the derivation rather than by trusting a claim about it.
/// The material separates the resources one minter issues.
#[must_use]
pub fn resource_address(
    hasher: &dyn Hasher,
    minter: impl Into<Address>,
    material: &[Vec<u8>],
) -> ResourceAddr {
    let minter_bytes = minter.into().to_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(1 + material.len());
    parts.push(&minter_bytes);
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
/// part — so a certificate and the state it describes agree by literal
/// byte equality, with the decoder's canonicity supplying the bijection
/// between the value list and its bytes.
#[must_use]
pub fn config_hash(hasher: &dyn Hasher, config_leaf: &[u8]) -> Hash32 {
    hasher.hash(DOMAIN_INSTANCE_CONFIG, &[config_leaf])
}

/// The bound on a value's nesting depth.
///
/// Admission rejects a deeper literal before it reaches the manifest hash.
/// A wire decoder is expected to bound nesting too — a value deep enough
/// to exhaust the native stack in `Clone` or `Drop` never reaches this
/// crate — and this bound is what makes a decoder that does not agree a
/// deterministic rejection rather than a divergence.
pub const MAX_VALUE_DEPTH: usize = 16;

/// The decoder nesting cap that admits exactly the values within
/// [`MAX_VALUE_DEPTH`].
///
/// One value level costs at most two decoder levels — the variant's
/// collection field and its hoisted element body — and adding a level costs
/// at least one more than a scalar leaf, so `2 * MAX_VALUE_DEPTH` admits
/// every value of admissible depth and refuses every deeper one. The
/// relation is pinned by test at both boundaries; a wire decoder for
/// literals passes this cap and gets [`check_value_depth`] as a decode-time
/// consequence rather than a pass afterwards.
///
/// [`check_value_depth`]: crate::admission
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
        resource: Address,
        /// What crosses the edge: a dynamic amount, or named instances.
        content: EdgeContent,
    },
    /// A fixed-arity product.
    Tuple(Vec<Self>),
    /// A bounded homogeneous sequence.
    List(Vec<Self>),
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

/// One declared access target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EffectTarget {
    /// A single substate leaf.
    Point(SubstateKey),
    /// One entry of an ordered collection, at a declared order key.
    Entry {
        /// The collection's owner.
        owner: Address,
        /// The collection's identity under the owner.
        collection: CollectionId,
        /// The entry's position in the collection's order-key space.
        order: u128,
    },
    /// A declared interval of an ordered collection's order-key space.
    ///
    /// The interval is access-stable: it stays valid whatever entries enter
    /// or leave it between signing and execution. Conflict against points
    /// and other ranges is interval overlap.
    Range {
        /// The collection's owner.
        owner: Address,
        /// The collection's identity under the owner.
        collection: CollectionId,
        /// Inclusive lower order-key bound.
        lo: u128,
        /// Inclusive upper order-key bound.
        hi: u128,
        /// The maximum entries execution may touch within the interval.
        cap: u32,
    },
}

impl EffectTarget {
    /// The owner whose prefix the target lives under — and therefore the
    /// target's shard.
    #[must_use]
    pub const fn owner(&self) -> Address {
        match self {
            Self::Point(key) => key.owner,
            Self::Entry { owner, .. } | Self::Range { owner, .. } => *owner,
        }
    }
}

/// A declared access: target plus mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Effect {
    /// What is accessed.
    pub target: EffectTarget,
    /// How it is accessed.
    pub mode: Mode,
}

/// Summing declared reserve amounts overflowed `u128`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("declared reserve amounts overflow")]
pub struct ReserveOverflow;

/// A set of declared accesses with union semantics: identical effects
/// dedup, and reserve amounts on the same target fold by summation, so the
/// set carries the transaction's total declared demand per key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectSet {
    by_target: BTreeMap<EffectTarget, BTreeSet<Mode>>,
}

impl EffectSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            by_target: BTreeMap::new(),
        }
    }

    /// Add one effect, folding reserve amounts on the same target.
    ///
    /// # Errors
    ///
    /// [`ReserveOverflow`] if the folded reserve amount exceeds `u128`.
    pub fn insert(&mut self, effect: Effect) -> Result<(), ReserveOverflow> {
        let modes = self.by_target.entry(effect.target).or_default();
        if let Mode::Reserve { amount } = effect.mode {
            let existing = modes.iter().find_map(|mode| match mode {
                Mode::Reserve { amount } => Some(*amount),
                _ => None,
            });
            if let Some(prior) = existing {
                let total = prior.checked_add(amount).ok_or(ReserveOverflow)?;
                modes.remove(&Mode::Reserve { amount: prior });
                modes.insert(Mode::Reserve { amount: total });
                return Ok(());
            }
        }
        modes.insert(effect.mode);
        Ok(())
    }

    /// Every effect in the set, in canonical (target, mode) order.
    pub fn iter(&self) -> impl Iterator<Item = Effect> + '_ {
        self.by_target.iter().flat_map(|(target, modes)| {
            modes.iter().map(move |mode| Effect {
                target: *target,
                mode: *mode,
            })
        })
    }

    /// The number of (target, mode) pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_target.values().map(BTreeSet::len).sum()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_target.is_empty()
    }

    /// The provision requirement of this effect set: the targets whose
    /// committed values a counterpart shard must carry — fresh reads and
    /// the prior values of read-modify-writes. Locked reads are
    /// client-proven, deltas read nothing, and reservation feasibility is
    /// judged at the owning shard, so none of them provision. A
    /// commutative-only leg therefore provisions nothing at all.
    #[must_use]
    pub fn provision_targets(&self) -> BTreeSet<EffectTarget> {
        self.by_target
            .iter()
            .filter(|(_, modes)| {
                modes
                    .iter()
                    .any(|mode| matches!(mode.kind(), ModeKind::Read | ModeKind::Write))
            })
            .map(|(target, _)| *target)
            .collect()
    }

    /// Whether the exact (target, mode) pair is present.
    #[must_use]
    pub fn contains(&self, effect: &Effect) -> bool {
        self.by_target
            .get(&effect.target)
            .is_some_and(|modes| modes.contains(&effect.mode))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_hbor::{assert_canonical, from_slice_with_depth};

    use super::{
        Address, AddressClass, EdgeContent, Effect, EffectSet, EffectTarget, LocalKey,
        MAX_VALUE_DEPTH, MAX_VALUE_WIRE_DEPTH, Mode, ModeKind, NativeRole, RoleId, SchemeId,
        SubstateKey, Value, child_key, compatible, component_address, config_hash, native_address,
        package_address, principal_address, resource_address, to_vec,
    };
    use crate::hash::{Hash32, TestHasher};
    use crate::metadata::PackageHash;
    use crate::vectors::{
        CONFIG_LEAF, PACKAGE, SALT, address_vector_lines, address_vectors, expected_classes,
    };

    #[test]
    fn compatibility_matrix() {
        use ModeKind::{Delta, Locked, Read, Reserve, Write};
        let kinds = [Read, Locked, Delta, Reserve, Write];
        let table = [
            [true, true, false, false, false],
            [true, true, true, true, true],
            [false, true, true, true, false],
            [false, true, true, true, false],
            [false, true, false, false, false],
        ];
        for (i, &a) in kinds.iter().enumerate() {
            for (j, &b) in kinds.iter().enumerate() {
                assert_eq!(compatible(a, b), table[i][j], "{a:?} vs {b:?}");
                assert_eq!(compatible(a, b), compatible(b, a), "symmetry {a:?}/{b:?}");
            }
        }
    }

    #[test]
    fn only_read_and_write_targets_provision() {
        // A counterpart shard has to carry what execution reads: fresh
        // reads, and the prior value a read-modify-write folds over.
        // A locked target cannot change, deltas read nothing, and a
        // reservation is judged where it lives — so a commutative-only
        // leg provisions nothing at all.
        let owner = Address::new([1; 31], AddressClass::Component);
        let target =
            |byte: u8| EffectTarget::Point(child_key(&TestHasher, owner, RoleId(byte.into()), &[]));
        let mut set = EffectSet::new();
        for (byte, mode) in [
            (1, Mode::Read),
            (2, Mode::Write),
            (3, Mode::Delta),
            (4, Mode::Reserve { amount: 5 }),
            (5, Mode::Locked),
        ] {
            set.insert(Effect {
                target: target(byte),
                mode,
            })
            .unwrap();
        }
        assert_eq!(
            set.provision_targets(),
            BTreeSet::from([target(1), target(2)])
        );

        // A cell carrying both a delta and a read still provisions: the
        // read is what needs the value.
        let mut mixed = EffectSet::new();
        mixed
            .insert(Effect {
                target: target(3),
                mode: Mode::Read,
            })
            .unwrap();
        mixed
            .insert(Effect {
                target: target(3),
                mode: Mode::Delta,
            })
            .unwrap();
        assert_eq!(mixed.provision_targets(), BTreeSet::from([target(3)]));

        assert!(EffectSet::new().provision_targets().is_empty());
    }

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
            resource: Address::new([7; 31], AddressClass::Component),
            content: EdgeContent::Fungible,
        });
        assert_canonical(&Value::Bucket {
            resource: Address::new([7; 31], AddressClass::Component),
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
    fn child_keys_separate_by_role_and_material() {
        let owner = Address::new([1; 31], AddressClass::Component);
        let a = child_key(&TestHasher, owner, RoleId(1), &[vec![9]]);
        assert_eq!(a, child_key(&TestHasher, owner, RoleId(1), &[vec![9]]));
        assert_ne!(a, child_key(&TestHasher, owner, RoleId(2), &[vec![9]]));
        assert_ne!(a, child_key(&TestHasher, owner, RoleId(1), &[vec![8]]));
        assert_ne!(a, child_key(&TestHasher, owner, RoleId(1), &[]));
        assert_eq!(a.owner, owner);
    }

    #[test]
    fn child_key_locals_separate_by_owner() {
        let a = child_key(
            &TestHasher,
            Address::new([1; 31], AddressClass::Component),
            RoleId(1),
            &[vec![9]],
        );
        let b = child_key(
            &TestHasher,
            Address::new([2; 31], AddressClass::Component),
            RoleId(1),
            &[vec![9]],
        );
        assert_ne!(a.local, b.local);
    }

    #[test]
    fn effect_set_folds_reserves_and_dedups() {
        let key = child_key(
            &TestHasher,
            Address::new([1; 31], AddressClass::Component),
            RoleId(1),
            &[],
        );
        let target = EffectTarget::Point(key);
        let mut set = EffectSet::new();
        set.insert(Effect {
            target,
            mode: Mode::Reserve { amount: 100 },
        })
        .unwrap();
        set.insert(Effect {
            target,
            mode: Mode::Reserve { amount: 50 },
        })
        .unwrap();
        set.insert(Effect {
            target,
            mode: Mode::Delta,
        })
        .unwrap();
        set.insert(Effect {
            target,
            mode: Mode::Delta,
        })
        .unwrap();
        assert_eq!(set.iter().count(), 2);
        assert!(set.contains(&Effect {
            target,
            mode: Mode::Reserve { amount: 150 },
        }));
        assert!(set.contains(&Effect {
            target,
            mode: Mode::Delta,
        }));

        let overflow = set.insert(Effect {
            target,
            mode: Mode::Reserve { amount: u128::MAX },
        });
        assert!(overflow.is_err());
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
                "resource/minted = f72ffe983b73e50f18db85a1cb300808acab0346e1d60fbe8683981bab88de04",
                "native/xrd = 6d533c845b52439ae3b1b23e2b1c40e96e9c96ec0c67c70c9b238f1b860d1a05",
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
    fn a_resource_separates_by_minter_and_material() {
        let config = config_hash(&TestHasher, CONFIG_LEAF);
        let minter = component_address(&TestHasher, PACKAGE, config, SALT);
        let other = component_address(&TestHasher, PACKAGE, config, Hash32([0x5c; 32]));
        let base = resource_address(&TestHasher, minter, &[b"unit".to_vec()]);

        assert_eq!(
            base,
            resource_address(&TestHasher, minter, &[b"unit".to_vec()])
        );
        assert_ne!(
            base,
            resource_address(&TestHasher, other, &[b"unit".to_vec()])
        );
        assert_ne!(
            base,
            resource_address(&TestHasher, minter, &[b"other".to_vec()])
        );
        // The minter is a framed part, so material cannot be chosen to
        // reproduce another minter's resource by shifting the boundary.
        assert_ne!(
            resource_address(&TestHasher, minter, &[b"ab".to_vec(), b"c".to_vec()]),
            resource_address(&TestHasher, minter, &[b"abc".to_vec()])
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
                &[vec![0x11; 32]],
            )
            .body(),
            native_address(&TestHasher, NativeRole(0x11)).body(),
        ];
        let unique: BTreeSet<[u8; 31]> = bodies.iter().copied().collect();
        assert_eq!(unique.len(), bodies.len());
    }
}
