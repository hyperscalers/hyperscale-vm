//! The trace-subset oracle: every recorded access must be covered by the
//! declared effect set.
//!
//! Coverage composes target inclusion with mode permission: a point access
//! is covered by the identical declared point, an entry access by the
//! identical declared entry or a declared range containing its order key,
//! and a scan by a declared range enclosing its interval with at least its
//! cap. A declared write permits the reads its read-modify-write implies;
//! every other mode permits exactly itself.

use hyperscale_vm_effects::{EffectSet, EffectTarget, ModeKind};

use crate::store::Access;

/// Whether a declared mode kind permits an access of the given kind.
#[must_use]
pub const fn permits(declared: ModeKind, access: ModeKind) -> bool {
    matches!(
        (declared, access),
        (ModeKind::Write, ModeKind::Read | ModeKind::Write)
            | (ModeKind::Read, ModeKind::Read)
            | (ModeKind::Snapshot, ModeKind::Snapshot)
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

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{
        Address, Effect, EffectSet, EffectTarget, Mode, ModeKind, RoleId, TestHasher, child_key,
    };

    use super::undeclared_accesses;
    use crate::store::Access;

    fn declared(effects: &[Effect]) -> EffectSet {
        let mut set = EffectSet::new();
        for effect in effects {
            set.insert(*effect).unwrap();
        }
        set
    }

    #[test]
    fn coverage_spans_write_implied_reads_and_range_membership() {
        let owner = Address([1; 16]);
        let cell = child_key(&TestHasher, owner, RoleId(1), &[]);
        let set = declared(&[
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Write,
            },
            Effect {
                target: EffectTarget::Range {
                    owner,
                    collection: RoleId(4),
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
                    collection: RoleId(4),
                    order: 15,
                },
                kind: ModeKind::Write,
            },
            // A sub-interval scan with a smaller cap.
            Access {
                target: EffectTarget::Range {
                    owner,
                    collection: RoleId(4),
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
    fn undeclared_key_mode_and_interval_escapes_are_caught() {
        let owner = Address([1; 16]);
        let cell = child_key(&TestHasher, owner, RoleId(1), &[]);
        let set = declared(&[
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Read,
            },
            Effect {
                target: EffectTarget::Range {
                    owner,
                    collection: RoleId(4),
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
                    collection: RoleId(4),
                    order: 15,
                },
                kind: ModeKind::Delta,
            },
            // An entry outside the declared interval.
            Access {
                target: EffectTarget::Entry {
                    owner,
                    collection: RoleId(4),
                    order: 21,
                },
                kind: ModeKind::Write,
            },
            // A scan wider than the declaration, and one with a larger cap.
            Access {
                target: EffectTarget::Range {
                    owner,
                    collection: RoleId(4),
                    lo: 5,
                    hi: 20,
                    cap: 8,
                },
                kind: ModeKind::Read,
            },
            Access {
                target: EffectTarget::Range {
                    owner,
                    collection: RoleId(4),
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
}
