//! Keys, values, modes, and effect targets — the vocabulary shared by the
//! DSL evaluator, the router, and the kernel.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Hbor, to_vec};
pub use hyperscale_vm_types::{Address, LocalKey, SubstateKey};

use crate::hash::Hasher;

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

const DOMAIN_CHILD: &[u8] = b"hyperscale-vm/child-key";

/// The canonical child key for role-bound state under `owner`.
///
/// The local half is the hash of the role and the material, truncated to 16
/// bytes — which is what makes level-one access ("the vault for resource R
/// under account A") pure computation, never a state read.
///
/// Sixteen bytes is a deliberate choice, not a leftover: it puts the local
/// half at a 64-bit birthday bound against collisions, and the collision
/// domain is one owner's own children, which the owner also chooses the
/// material for. The leaf key is the owner prefix plus this half, so a
/// collision cannot cross a prefix and cannot cross a shard.
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

/// An access mode with its statically evaluated parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// Fresh coherent read of committed state.
    Read,
    /// Read of a locked substate: creation-fixed configuration, identical
    /// at every version.
    ///
    /// Immutability is what the mode buys and what it costs. Because no
    /// version of the target differs, the read needs no coherence and no
    /// proof: it carries no obligation, takes no admission key, and makes
    /// its owner no participant — the one mode a shard can serve without
    /// joining the transaction. And because it is verified by the target
    /// being locked rather than by attestation, it says nothing at all
    /// about mutable state; a read of that is [`Mode::Read`].
    Locked,
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
            Self::Locked => ModeKind::Locked,
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
    /// See [`Mode::Locked`].
    Locked,
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
/// A locked read is compatible with everything, and no longer by
/// assertion: its target is locked, and every mutating mode refuses a locked
/// target, so nothing can hold a conflicting mode on one. A fresh read
/// excludes every mutation; delta and reserve commute with each other;
/// write excludes everything but a locked read. Symmetric by construction.
#[must_use]
pub const fn compatible(a: ModeKind, b: ModeKind) -> bool {
    matches!(
        (a, b),
        (ModeKind::Locked, _)
            | (_, ModeKind::Locked)
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
        Address, Effect, EffectSet, EffectTarget, LocalKey, MAX_VALUE_DEPTH, MAX_VALUE_WIRE_DEPTH,
        Mode, ModeKind, RoleId, SubstateKey, Value, child_key, compatible, to_vec,
    };
    use crate::hash::TestHasher;

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
        let owner = Address([1; 16]);
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
                owner: Address([5; 16]),
                local: LocalKey([6; 16]),
            }),
        ]);
        assert_eq!(value.canonical_bytes(), to_vec(&value).unwrap());
        assert_canonical(&value);
        assert_canonical(&Value::Bucket {
            resource: Address([7; 16]),
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
