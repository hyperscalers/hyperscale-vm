//! Keys, values, modes, and effect targets — the vocabulary shared by the
//! DSL evaluator, the router, and the kernel.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::hash::Hasher;

/// A global object's address: its 16-byte owner prefix in the JMT key space.
///
/// Every substate an object owns lives under this prefix, and a shard
/// boundary never cuts through a prefix, so an address resolves to exactly
/// one shard.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 16]);

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// The local half of a substate key, assigned within an owner's prefix.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalKey(pub [u8; 16]);

impl fmt::Debug for LocalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalKey(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// A full JMT leaf key: owner prefix followed by the local half.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubstateKey {
    /// The owning object's address; fixes the key's shard.
    pub owner: Address,
    /// The slot within the owner's prefix.
    pub local: LocalKey,
}

/// A shard identity, as resolved from an address prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId(pub u16);

/// A role tag naming a kernel-addressed slot under an owner.
///
/// The role says which child — a vault, a claims cell, a field group, an
/// ordered collection — a canonical address refers to. Role values are
/// package conventions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoleId(pub u16);

const DOMAIN_CHILD: &[u8] = b"hyperscale-vm/child-key";

/// The canonical child key for role-bound state under `owner`.
///
/// The local half is the hash of the role and the material, truncated to 16
/// bytes — which is what makes level-one access ("the vault for resource R
/// under account A") pure computation, never a state read.
#[must_use]
pub fn child_key(
    hasher: &dyn Hasher,
    owner: Address,
    role: RoleId,
    material: &[Vec<u8>],
) -> SubstateKey {
    let role_bytes = role.0.to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(1 + material.len());
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

/// A typed value the DSL evaluates over: manifest literals, edge
/// projections, instance configuration fields, and everything derivable
/// from them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// The routable projection of a value edge: its static resource type.
    /// Amounts are dynamic and never visible to the DSL.
    Bucket {
        /// The resource the edge carries.
        resource: Address,
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
    /// child-address material and manifest identity. Deliberately not a
    /// wire format.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::U64(v) => {
                out.push(1);
                out.extend(v.to_le_bytes());
            }
            Self::U128(v) => {
                out.push(2);
                out.extend(v.to_le_bytes());
            }
            Self::Bytes(bytes) => {
                out.push(3);
                out.extend((bytes.len() as u64).to_le_bytes());
                out.extend(bytes);
            }
            Self::Address(addr) => {
                out.push(4);
                out.extend(addr.0);
            }
            Self::Key(key) => {
                out.push(5);
                out.extend(key.owner.0);
                out.extend(key.local.0);
            }
            Self::Bucket { resource } => {
                out.push(6);
                out.extend(resource.0);
            }
            Self::Tuple(values) => {
                out.push(7);
                out.extend((values.len() as u64).to_le_bytes());
                for value in values {
                    value.write_canonical(out);
                }
            }
            Self::List(values) => {
                out.push(8);
                out.extend((values.len() as u64).to_le_bytes());
                for value in values {
                    value.write_canonical(out);
                }
            }
        }
    }
}

/// A snapshot read's staleness window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Window {
    /// Pinned to an attested version no older than this many versions; the
    /// read carries a proof obligation.
    Bounded(u64),
    /// A permanently locked substate — verified once, cached process-wide,
    /// never a proof obligation and never a participant.
    Unbounded,
}

/// An access mode with its statically evaluated parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// Fresh coherent read of committed state.
    Read,
    /// Read pinned to an attested state version.
    Snapshot {
        /// The declared staleness window.
        window: Window,
    },
    /// Unconditional commutative increment or decrement; the amount is
    /// dynamic and never part of the declaration.
    Delta,
    /// Conditional decrement, feasible iff committed balance minus prior
    /// reservations covers the declared amount.
    Reserve {
        /// The statically evaluated amount feasibility is judged against.
        amount: u128,
    },
    /// Exclusive read-modify-write.
    Write,
}

impl Mode {
    /// The mode's kind, for scheduling compatibility.
    #[must_use]
    pub const fn kind(&self) -> ModeKind {
        match self {
            Self::Read => ModeKind::Read,
            Self::Snapshot { .. } => ModeKind::Snapshot,
            Self::Delta => ModeKind::Delta,
            Self::Reserve { .. } => ModeKind::Reserve,
            Self::Write => ModeKind::Write,
        }
    }
}

/// Mode kinds, parameter-free, as scheduling compatibility consumes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModeKind {
    /// See [`Mode::Read`].
    Read,
    /// See [`Mode::Snapshot`].
    Snapshot,
    /// See [`Mode::Delta`].
    Delta,
    /// See [`Mode::Reserve`].
    Reserve,
    /// See [`Mode::Write`].
    Write,
}

/// The scheduling compatibility relation: whether two in-flight
/// transactions may hold these modes on the same key concurrently.
///
/// Snapshot is compatible with everything; a fresh read excludes every
/// mutation; delta and reserve commute with each other; write excludes
/// everything but snapshot. Symmetric by construction.
#[must_use]
pub const fn compatible(a: ModeKind, b: ModeKind) -> bool {
    matches!(
        (a, b),
        (ModeKind::Snapshot, _)
            | (_, ModeKind::Snapshot)
            | (ModeKind::Read, ModeKind::Read)
            | (
                ModeKind::Delta | ModeKind::Reserve,
                ModeKind::Delta | ModeKind::Reserve
            )
    )
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
        /// The collection's role under the owner.
        collection: RoleId,
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
        /// The collection's role under the owner.
        collection: RoleId,
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
    /// the prior values of read-modify-writes. Snapshot reads are
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
    use super::{
        Address, Effect, EffectSet, EffectTarget, Mode, ModeKind, RoleId, child_key, compatible,
    };
    use crate::hash::TestHasher;

    #[test]
    fn compatibility_matrix() {
        use ModeKind::{Delta, Read, Reserve, Snapshot, Write};
        let kinds = [Read, Snapshot, Delta, Reserve, Write];
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
    fn child_keys_separate_by_role_and_material() {
        let owner = Address([1; 16]);
        let a = child_key(&TestHasher, owner, RoleId(1), &[vec![9]]);
        assert_eq!(a, child_key(&TestHasher, owner, RoleId(1), &[vec![9]]));
        assert_ne!(a, child_key(&TestHasher, owner, RoleId(2), &[vec![9]]));
        assert_ne!(a, child_key(&TestHasher, owner, RoleId(1), &[vec![8]]));
        assert_ne!(a, child_key(&TestHasher, owner, RoleId(1), &[]));
        assert_eq!(a.owner, owner);
    }

    #[test]
    fn effect_set_folds_reserves_and_dedups() {
        let key = child_key(&TestHasher, Address([1; 16]), RoleId(1), &[]);
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
}
