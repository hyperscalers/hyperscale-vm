//! The trace-subset oracle: every recorded access must be covered by the
//! declared effect set.
//!
//! Coverage composes target inclusion with mode permission: a point access
//! is covered by the identical declared point, an entry access by the
//! identical declared entry or a declared range containing its order key,
//! and a scan by a declared range enclosing its interval with at least its
//! cap. A declared write permits the reads its read-modify-write implies;
//! every other mode permits exactly itself.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{Address, CollectionId, EffectSet, EffectTarget, ModeKind};

use crate::store::{Access, Base};

/// Whether a declared mode kind permits an access of the given kind.
#[must_use]
pub const fn permits(declared: ModeKind, access: ModeKind) -> bool {
    matches!(
        (declared, access),
        (ModeKind::Write, ModeKind::Read | ModeKind::Write)
            | (ModeKind::Read, ModeKind::Read)
            | (ModeKind::Locked, ModeKind::Locked)
            | (ModeKind::Delta, ModeKind::Delta)
            | (ModeKind::Reserve, ModeKind::Reserve)
    )
}

/// Whether a declared target covers an accessed one.
#[must_use]
pub fn target_covers(declared: &EffectTarget, accessed: &EffectTarget) -> bool {
    match (declared, accessed) {
        (EffectTarget::Point(declared_key), EffectTarget::Point(accessed_key)) => {
            declared_key == accessed_key
        }
        (
            EffectTarget::Entry {
                owner: declared_owner,
                collection: declared_collection,
                order: declared_order,
            },
            EffectTarget::Entry {
                owner: accessed_owner,
                collection: accessed_collection,
                order: accessed_order,
            },
        ) => {
            declared_owner == accessed_owner
                && declared_collection == accessed_collection
                && declared_order == accessed_order
        }
        (
            EffectTarget::Range {
                owner: declared_owner,
                collection: declared_collection,
                lo,
                hi,
                ..
            },
            EffectTarget::Entry {
                owner: accessed_owner,
                collection: accessed_collection,
                order,
            },
        ) => {
            declared_owner == accessed_owner
                && declared_collection == accessed_collection
                && (lo..=hi).contains(&order)
        }
        // A declared entry materializes as the width-one interval at its
        // order, so reading through that capability records a one-entry
        // scan of exactly the declared key. The scan is the entry.
        (
            EffectTarget::Entry {
                owner: declared_owner,
                collection: declared_collection,
                order,
            },
            EffectTarget::Range {
                owner: accessed_owner,
                collection: accessed_collection,
                lo,
                hi,
                cap,
            },
        ) => {
            declared_owner == accessed_owner
                && declared_collection == accessed_collection
                && *lo == *order
                && *hi == *order
                && *cap <= 1
        }
        (
            EffectTarget::Range {
                owner: declared_owner,
                collection: declared_collection,
                lo: declared_lo,
                hi: declared_hi,
                cap: declared_cap,
            },
            EffectTarget::Range {
                owner: accessed_owner,
                collection: accessed_collection,
                lo: accessed_lo,
                hi: accessed_hi,
                cap: accessed_cap,
            },
        ) => {
            declared_owner == accessed_owner
                && declared_collection == accessed_collection
                && declared_lo <= accessed_lo
                && accessed_hi <= declared_hi
                && accessed_cap <= declared_cap
        }
        _ => false,
    }
}

/// Whether one access is covered by any declared effect.
#[must_use]
pub fn covered(access: &Access, declared: &EffectSet) -> bool {
    declared.iter().any(|effect| {
        target_covers(&effect.target, &access.target) && permits(effect.mode.kind(), access.kind)
    })
}

/// Every access in the trace not covered by the declared set. The oracle's
/// verdict: this must be empty after every execution, in every test,
/// permanently.
#[must_use]
pub fn undeclared_accesses(trace: &[Access], declared: &EffectSet) -> Vec<Access> {
    trace
        .iter()
        .filter(|access| !covered(access, declared))
        .cloned()
        .collect()
}

/// The instance ids held in more than one place, per-id linearity's
/// verdict: this must be empty after every wave, permanently.
///
/// Scans each given holdings collection in the committed store and
/// reports every order key present under two or more of them.
///
/// Asserted over settled state rather than over per-receipt changes,
/// because that is what the invariant says: a transfer chain inside one
/// wave creates an entry it later removes and nets to a single holding,
/// while an id genuinely landing twice is two entries no netting erases.
#[must_use]
pub fn multiply_held_ids(store: &dyn Base, holdings: &[(Address, CollectionId)]) -> Vec<u128> {
    let mut holders: BTreeMap<u128, usize> = BTreeMap::new();
    for &(holder, collection) in holdings {
        for (order, _) in store.entries_in_range(holder, collection, 0, u128::MAX, usize::MAX) {
            *holders.entry(order).or_default() += 1;
        }
    }
    holders
        .into_iter()
        .filter(|&(_, count)| count > 1)
        .map(|(order, _)| order)
        .collect()
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{
        Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, Mode, ModeKind,
        RoleId, TestHasher, child_key, collection_id,
    };

    use super::{multiply_held_ids, undeclared_accesses};
    use crate::store::{Access, MemoryStore, SubstateStore};

    fn declared(effects: &[Effect]) -> EffectSet {
        let mut set = EffectSet::new();
        for effect in effects {
            set.insert(*effect).unwrap();
        }
        set
    }

    #[test]
    fn coverage_spans_write_implied_reads_and_range_membership() {
        let owner = Address::new([1; 31], AddressClass::Component);
        let cell = child_key(&TestHasher, owner, RoleId(1), &[]);
        let set = declared(&[
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Write,
            },
            Effect {
                target: EffectTarget::Range {
                    owner,
                    collection: CollectionId([4; 16]),
                    lo: 10,
                    hi: 20,
                    cap: 8,
                },
                mode: Mode::Write,
            },
        ]);

        let trace = [
            // A read under a declared write: the read-modify-write half.
            Access {
                target: EffectTarget::Point(cell),
                kind: ModeKind::Read,
            },
            Access {
                target: EffectTarget::Point(cell),
                kind: ModeKind::Write,
            },
            // An entry write inside the declared interval.
            Access {
                target: EffectTarget::Entry {
                    owner,
                    collection: CollectionId([4; 16]),
                    order: 15,
                },
                kind: ModeKind::Write,
            },
            // A sub-interval scan with a smaller cap.
            Access {
                target: EffectTarget::Range {
                    owner,
                    collection: CollectionId([4; 16]),
                    lo: 12,
                    hi: 18,
                    cap: 4,
                },
                kind: ModeKind::Read,
            },
        ];
        assert_eq!(undeclared_accesses(&trace, &set), Vec::new());
    }

    #[test]
    fn a_declared_entry_covers_its_own_width_one_scan() {
        let owner = Address::new([1; 31], AddressClass::Component);
        let entry = |mode| Effect {
            target: EffectTarget::Entry {
                owner,
                collection: CollectionId([4; 16]),
                order: 15,
            },
            mode,
        };
        let scan = |lo, hi, cap| Access {
            target: EffectTarget::Range {
                owner,
                collection: CollectionId([4; 16]),
                lo,
                hi,
                cap,
            },
            kind: ModeKind::Read,
        };
        // Reading through the entry's capability is the entry.
        let set = declared(&[entry(Mode::Read)]);
        assert_eq!(undeclared_accesses(&[scan(15, 15, 1)], &set), Vec::new());
        // The write-implied read too.
        let written = declared(&[entry(Mode::Write)]);
        assert_eq!(
            undeclared_accesses(&[scan(15, 15, 1)], &written),
            Vec::new()
        );
        // A wider interval, a shifted one, or a larger cap is not the
        // declared entry.
        for escape in [scan(15, 16, 1), scan(14, 14, 1), scan(15, 15, 2)] {
            assert_eq!(
                undeclared_accesses(std::slice::from_ref(&escape), &set),
                vec![escape.clone()]
            );
        }
    }

    #[test]
    fn undeclared_key_mode_and_interval_escapes_are_caught() {
        let owner = Address::new([1; 31], AddressClass::Component);
        let cell = child_key(&TestHasher, owner, RoleId(1), &[]);
        let set = declared(&[
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Read,
            },
            Effect {
                target: EffectTarget::Range {
                    owner,
                    collection: CollectionId([4; 16]),
                    lo: 10,
                    hi: 20,
                    cap: 8,
                },
                mode: Mode::Write,
            },
        ]);

        let escapes = [
            // An undeclared key.
            Access {
                target: EffectTarget::Point(child_key(&TestHasher, owner, RoleId(2), &[])),
                kind: ModeKind::Read,
            },
            // A declared read does not permit a write.
            Access {
                target: EffectTarget::Point(cell),
                kind: ModeKind::Write,
            },
            // A declared write range does not permit deltas.
            Access {
                target: EffectTarget::Entry {
                    owner,
                    collection: CollectionId([4; 16]),
                    order: 15,
                },
                kind: ModeKind::Delta,
            },
            // An entry outside the declared interval.
            Access {
                target: EffectTarget::Entry {
                    owner,
                    collection: CollectionId([4; 16]),
                    order: 21,
                },
                kind: ModeKind::Write,
            },
            // A scan wider than the declaration, and one with a larger cap.
            Access {
                target: EffectTarget::Range {
                    owner,
                    collection: CollectionId([4; 16]),
                    lo: 5,
                    hi: 20,
                    cap: 8,
                },
                kind: ModeKind::Read,
            },
            Access {
                target: EffectTarget::Range {
                    owner,
                    collection: CollectionId([4; 16]),
                    lo: 10,
                    hi: 20,
                    cap: 9,
                },
                kind: ModeKind::Read,
            },
        ];
        for escape in &escapes {
            assert_eq!(
                undeclared_accesses(std::slice::from_ref(escape), &set),
                vec![escape.clone()],
                "{escape:?} must be caught"
            );
        }
    }

    #[test]
    fn an_id_held_twice_is_the_linearity_verdict() {
        let resource_material = [7u8];
        let holdings: Vec<(Address, CollectionId)> = [1u8, 2]
            .into_iter()
            .map(|byte| {
                let holder = Address::new([byte; 31], AddressClass::Component);
                let collection = collection_id(
                    &TestHasher,
                    holder,
                    RoleId(12),
                    &[resource_material.to_vec()],
                );
                (holder, collection)
            })
            .collect();

        let mut store = MemoryStore::new();
        let write = |store: &mut MemoryStore, slot: usize, order: u128| {
            let (holder, collection) = holdings[slot];
            store
                .entry_write(holder, collection, order, vec![1])
                .unwrap();
        };
        write(&mut store, 0, 7);
        write(&mut store, 1, 9);
        assert_eq!(
            multiply_held_ids(&store, &holdings),
            Vec::<u128>::new(),
            "disjoint holdings are linear"
        );

        write(&mut store, 1, 7);
        assert_eq!(
            multiply_held_ids(&store, &holdings),
            vec![7],
            "the same id in two holdings collections is the violation"
        );
    }
}
