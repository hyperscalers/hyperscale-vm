//! Scheduling conflict: target overlap composed with mode compatibility.
//!
//! Two in-flight effects conflict iff their targets overlap and their
//! modes are incompatible under the lattice's compatibility relation.
//! Overlap is interval arithmetic over typed targets: point keys and
//! collection entries live in disjoint key spaces, entries sit inside
//! ranges by order-key membership, and ranges overlap by interval
//! intersection. Caps never influence overlap — they bound execution, not
//! the declared key space.

use hyperscale_vm_effects::{Effect, EffectTarget, compatible};

/// Whether two declared targets can name any common state.
#[must_use]
pub fn targets_overlap(a: &EffectTarget, b: &EffectTarget) -> bool {
    match (a, b) {
        (EffectTarget::Point(left), EffectTarget::Point(right)) => left == right,
        (
            EffectTarget::Entry {
                owner: left_owner,
                collection: left_collection,
                order: left_order,
            },
            EffectTarget::Entry {
                owner: right_owner,
                collection: right_collection,
                order: right_order,
            },
        ) => {
            left_owner == right_owner
                && left_collection == right_collection
                && left_order == right_order
        }
        (
            EffectTarget::Entry {
                owner: entry_owner,
                collection: entry_collection,
                order,
            },
            EffectTarget::Range {
                owner: range_owner,
                collection: range_collection,
                lo,
                hi,
                ..
            },
        )
        | (
            EffectTarget::Range {
                owner: range_owner,
                collection: range_collection,
                lo,
                hi,
                ..
            },
            EffectTarget::Entry {
                owner: entry_owner,
                collection: entry_collection,
                order,
            },
        ) => {
            entry_owner == range_owner
                && entry_collection == range_collection
                && (lo..=hi).contains(&order)
        }
        (
            EffectTarget::Range {
                owner: left_owner,
                collection: left_collection,
                lo: left_lo,
                hi: left_hi,
                ..
            },
            EffectTarget::Range {
                owner: right_owner,
                collection: right_collection,
                lo: right_lo,
                hi: right_hi,
                ..
            },
        ) => {
            left_owner == right_owner
                && left_collection == right_collection
                && left_lo <= right_hi
                && right_lo <= left_hi
        }
        // Point keys are hashed locals; collection entries live in order
        // space. The two can never alias.
        (EffectTarget::Point(_), _) | (_, EffectTarget::Point(_)) => false,
    }
}

/// Whether two declared effects exclude each other from concurrent
/// scheduling.
#[must_use]
pub fn conflicts(a: &Effect, b: &Effect) -> bool {
    targets_overlap(&a.target, &b.target) && !compatible(a.mode.kind(), b.mode.kind())
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{
        Address, AddressClass, CollectionId, Effect, EffectTarget, Mode, ModeKind, RoleId,
        TestHasher, child_key,
    };

    use super::{conflicts, targets_overlap};

    fn owner(byte: u8) -> Address {
        Address::new([byte; 31], AddressClass::Component)
    }

    fn point(byte: u8) -> EffectTarget {
        EffectTarget::Point(child_key(&TestHasher, owner(byte), RoleId(1), &[]))
    }

    fn entry(order: u128) -> EffectTarget {
        EffectTarget::Entry {
            owner: owner(1),
            collection: CollectionId([4; 16]),
            order,
        }
    }

    fn range(lo: u128, hi: u128) -> EffectTarget {
        EffectTarget::Range {
            owner: owner(1),
            collection: CollectionId([4; 16]),
            lo,
            hi,
            cap: 8,
        }
    }

    const fn mode_of(kind: ModeKind) -> Mode {
        match kind {
            ModeKind::Read => Mode::Read,
            ModeKind::Locked => Mode::Locked,
            ModeKind::Delta => Mode::Delta,
            ModeKind::Reserve => Mode::Reserve { amount: 1 },
            ModeKind::Write => Mode::Write,
        }
    }

    #[test]
    fn same_key_conflicts_follow_the_compatibility_matrix() {
        use ModeKind::{Delta, Locked, Read, Reserve, Write};
        let kinds = [Read, Locked, Delta, Reserve, Write];
        // The complement of the lattice's compatibility table.
        let conflict_table = [
            [false, false, true, true, true],
            [false, false, false, false, false],
            [true, false, false, false, true],
            [true, false, false, false, true],
            [true, false, true, true, true],
        ];
        for (i, &a) in kinds.iter().enumerate() {
            for (j, &b) in kinds.iter().enumerate() {
                let left = Effect {
                    target: point(1),
                    mode: mode_of(a),
                };
                let right = Effect {
                    target: point(1),
                    mode: mode_of(b),
                };
                assert_eq!(
                    conflicts(&left, &right),
                    conflict_table[i][j],
                    "{a:?}/{b:?}"
                );
            }
        }
        // Distinct keys never conflict, whatever the modes.
        let left = Effect {
            target: point(1),
            mode: Mode::Write,
        };
        let right = Effect {
            target: point(2),
            mode: Mode::Write,
        };
        assert!(!conflicts(&left, &right));
    }

    #[test]
    fn interval_overlap_drives_collection_conflicts() {
        // Entry inside a range: overlap; outside: none.
        assert!(targets_overlap(&entry(10), &range(5, 15)));
        assert!(targets_overlap(&entry(5), &range(5, 15)));
        assert!(targets_overlap(&entry(15), &range(5, 15)));
        assert!(!targets_overlap(&entry(4), &range(5, 15)));
        assert!(!targets_overlap(&entry(16), &range(5, 15)));

        // Range-range intersection, including single-order touch.
        assert!(targets_overlap(&range(5, 15), &range(15, 20)));
        assert!(targets_overlap(&range(5, 15), &range(0, 30)));
        assert!(!targets_overlap(&range(5, 15), &range(16, 20)));

        // A different collection or owner is a different key space.
        let other_collection = EffectTarget::Range {
            owner: owner(1),
            collection: CollectionId([5; 16]),
            lo: 0,
            hi: 100,
            cap: 8,
        };
        assert!(!targets_overlap(&range(0, 100), &other_collection));
        let other_owner = EffectTarget::Entry {
            owner: owner(2),
            collection: CollectionId([4; 16]),
            order: 10,
        };
        assert!(!targets_overlap(&range(0, 100), &other_owner));

        // Point keys and collection targets can never alias.
        assert!(!targets_overlap(&point(1), &entry(10)));
        assert!(!targets_overlap(&point(1), &range(0, u128::MAX)));

        // Overlapping exclusive writes conflict; a locked range rides
        // along with anything.
        let write_range = Effect {
            target: range(5, 15),
            mode: Mode::Write,
        };
        let write_entry = Effect {
            target: entry(10),
            mode: Mode::Write,
        };
        assert!(conflicts(&write_range, &write_entry));
        let locked_range = Effect {
            target: range(0, 100),
            mode: Mode::Locked,
        };
        assert!(!conflicts(&locked_range, &write_range));
    }
}
