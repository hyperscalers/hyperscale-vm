//! What one transaction says about state.
//!
//! Two ways of saying it, because two kinds of access earn two kinds of
//! answer. An exclusive write knows the value it leaves and reports it
//! absolutely. A commutative access — a delta, a settled reservation —
//! knows only what it moved, and reporting *that* is what keeps the
//! answer true no matter what else touched the cell: an absolute
//! computed against one baseline is wrong the moment a sibling the
//! baseline excluded also lands, while a movement composes with it.
//!
//! An embedder commits absolutes, so movements are folded down by
//! [`StateWrites::resolve`] against whatever the cell holds when the
//! change actually applies. Doing that early — at execution, against the
//! baseline the transaction happened to read — is what throws the
//! property away. `None` is a removal: a drained amount cell resolves to
//! an absent cell, never to an encoded zero.

use std::collections::BTreeMap;

use hyperscale_hbor::{Hash32, Hbor, to_vec};

use crate::address::SubstateKey;
use crate::amount::{amount_cell, read_amount};

/// The bytes one committed cell value may carry — one bound for a cell
/// wherever it travels, in a receipt or a provision.
pub const MAX_CELL_VALUE_LEN: usize = 2 * 1024 * 1024;

/// One transaction's owned state change, keyed canonically.
///
/// Both maps decode only in strictly ascending key order, so every
/// encoding is canonical by construction and equal writes hash equal on
/// every replica.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
#[hbor(validate = cell_values_fit)]
pub struct StateWrites {
    /// The committed value per exclusively written cell, or `None` for a
    /// removal.
    pub cells: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    /// What this transaction moved on each amount cell it reached
    /// commutatively, relative to whatever the cell holds when the
    /// movement applies.
    ///
    /// A cell never appears in both maps: an access is exclusive or it is
    /// commutative, and the capability that granted it decided which.
    pub movements: BTreeMap<SubstateKey, Movement>,
}

/// A commutative change to one amount cell: checked credit and debit
/// totals, relative to whatever the cell holds.
///
/// Recording the movement rather than the value it would produce is what
/// makes a receipt schedule-invariant — another transaction's compatible
/// movement on the same cell cannot leak into this one, and neither
/// overwrites the other when both settle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hbor)]
pub struct Movement {
    /// Total credited.
    pub credit: u128,
    /// Total debited.
    pub debit: u128,
}

impl Movement {
    /// This movement followed by `next` on the same cell.
    ///
    /// Saturating on each side rather than checked: the totals are
    /// bounded by the balances that fed them, and a sum that could not
    /// overflow a cell cannot overflow here.
    #[must_use]
    pub const fn then(self, next: Self) -> Self {
        Self {
            credit: self.credit.saturating_add(next.credit),
            debit: self.debit.saturating_add(next.debit),
        }
    }

    /// `before` with this movement applied, or `None` if the debit runs
    /// past what the cell holds.
    #[must_use]
    pub fn apply(self, before: u128) -> Option<u128> {
        before.checked_add(self.credit)?.checked_sub(self.debit)
    }
}

impl StateWrites {
    /// Fold the movements onto the cells, against whatever each moved
    /// cell holds at the point the change applies.
    ///
    /// This is where a commutative change stops being relative and
    /// becomes a value an embedder can commit, and it belongs at the
    /// moment of application rather than the moment of execution:
    /// `prior` is the state the change lands on, which is not the state
    /// the transaction read. This receipt's own exclusive write to a
    /// cell stands in for `prior` where there is one; an absent cell
    /// reads as zero, and a drained one resolves to a removal.
    ///
    /// A debit past what the cell holds cannot arise — the kernel judged
    /// it against committed balance less outstanding holds before
    /// recording the movement — so it saturates rather than raising an
    /// error no caller could act on at settlement time.
    #[must_use]
    pub fn resolve(&self, prior: &mut dyn FnMut(SubstateKey) -> Option<Vec<u8>>) -> SettledWrites {
        let mut cells = self.cells.clone();
        for (key, movement) in &self.movements {
            let before = cells
                .get(key)
                .map_or_else(|| prior(*key), Clone::clone)
                .and_then(|bytes| read_amount(&bytes))
                .unwrap_or(0);
            let after = movement.apply(before).unwrap_or(0);
            cells.insert(*key, amount_cell(after).map(|cell| cell.to_vec()));
        }
        SettledWrites { cells }
    }

    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.movements.is_empty()
    }

    /// The canonical commitment to these writes: `hash_fn` over the
    /// canonical encoding.
    ///
    /// # Panics
    ///
    /// Panics if the encoding exceeds the encoder's bounds, which no
    /// writes map within the decode caps can.
    #[must_use]
    pub fn root(&self, hash_fn: fn(&[u8]) -> [u8; 32]) -> Hash32 {
        Hash32(hash_fn(
            &to_vec(self).expect("state writes stay within the encoder's bounds"),
        ))
    }
}

/// Cell values an embedder may commit: absolutes and nothing else.
///
/// Reachable only through [`StateWrites::resolve`] and
/// [`Self::from_absolutes`], so a movement cannot arrive somewhere that
/// stores values without someone having said what it moved from. That
/// matters more than it sounds: every consumer that commits state used
/// to walk `cells` and would have dropped a movement silently, attesting
/// a root missing the change rather than failing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettledWrites {
    cells: BTreeMap<SubstateKey, Option<Vec<u8>>>,
}

impl SettledWrites {
    /// Writes that are already values — genesis, a provision, a store's
    /// own snapshot. Nothing here moved, so nothing needs resolving.
    #[must_use]
    pub const fn from_absolutes(cells: BTreeMap<SubstateKey, Option<Vec<u8>>>) -> Self {
        Self { cells }
    }

    /// The committed value per changed cell, or `None` for a removal.
    #[must_use]
    pub const fn cells(&self) -> &BTreeMap<SubstateKey, Option<Vec<u8>>> {
        &self.cells
    }

    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Take the cells, for a consumer that owns them from here.
    #[must_use]
    pub fn into_cells(self) -> BTreeMap<SubstateKey, Option<Vec<u8>>> {
        self.cells
    }
}

impl From<SettledWrites> for StateWrites {
    /// Values are a receipt payload like any other — they are the half
    /// of one that never moved. The reverse needs a prior and so is
    /// [`StateWrites::resolve`], not a conversion.
    fn from(settled: SettledWrites) -> Self {
        Self {
            cells: settled.into_cells(),
            movements: BTreeMap::new(),
        }
    }
}

fn cell_values_fit(writes: &StateWrites) -> Result<(), &'static str> {
    if writes
        .cells
        .values()
        .flatten()
        .all(|value| value.len() <= MAX_CELL_VALUE_LEN)
    {
        Ok(())
    } else {
        Err("a cell value exceeds the cell cap")
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{DecodeError, assert_canonical, from_slice, to_vec};

    use super::{MAX_CELL_VALUE_LEN, Movement, StateWrites};
    use crate::address::{Address, LocalKey, SubstateKey};
    use crate::amount::{amount_cell, read_amount};

    fn key(owner: u8, local: u8) -> SubstateKey {
        SubstateKey {
            owner: Address([owner; 16]),
            local: LocalKey([local; 16]),
        }
    }

    #[test]
    fn writes_are_canonical() {
        let mut writes = StateWrites::default();
        writes.cells.insert(key(1, 1), Some(vec![7]));
        writes.cells.insert(key(1, 2), None);
        writes.cells.insert(key(2, 1), Some(vec![]));
        assert_canonical(&writes);
        assert_canonical(&StateWrites::default());
    }

    #[test]
    fn the_root_is_the_hash_of_the_encoding() {
        let hash_fn = |bytes: &[u8]| {
            let mut out = [0u8; 32];
            out[..8].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            out
        };
        let mut writes = StateWrites::default();
        assert_eq!(
            writes.root(hash_fn).0[..8],
            (to_vec(&writes).unwrap().len() as u64).to_le_bytes(),
        );
        writes.cells.insert(key(1, 1), Some(vec![7]));
        assert_eq!(
            writes.root(hash_fn).0[..8],
            (to_vec(&writes).unwrap().len() as u64).to_le_bytes(),
        );
    }

    #[test]
    fn an_oversized_cell_value_rejects_at_decode() {
        // Built by hand: the derive's validate hook runs at decode, so an
        // oversized value is refused on arrival, whatever built it.
        let mut writes = StateWrites::default();
        writes
            .cells
            .insert(key(1, 1), Some(vec![0; MAX_CELL_VALUE_LEN + 1]));
        let bytes = to_vec(&writes).unwrap();
        assert!(matches!(
            from_slice::<StateWrites>(&bytes),
            Err(DecodeError::FailedValidation(_))
        ));
    }

    /// Two movements on one cell compose whichever order they resolve
    /// in — the property absolutes do not have, and the reason a receipt
    /// carries movements at all.
    #[test]
    fn movements_on_one_cell_compose_in_either_order() {
        let vault = key(1, 1);
        let debit = |amount: u128| {
            let mut writes = StateWrites::default();
            writes.movements.insert(
                vault,
                Movement {
                    credit: 0,
                    debit: amount,
                },
            );
            writes
        };
        let start = amount_cell(1_000).map(|cell| cell.to_vec());

        // Whichever settles first, the second resolves against what the
        // first left, and the pair lands on the same value.
        let first_then_second = {
            let after_first = debit(300).resolve(&mut |_| start.clone());
            debit(400)
                .resolve(&mut |k| after_first.cells().get(&k).cloned().flatten())
                .cells()[&vault]
                .clone()
        };
        let second_then_first = {
            let after_second = debit(400).resolve(&mut |_| start.clone());
            debit(300)
                .resolve(&mut |k| after_second.cells().get(&k).cloned().flatten())
                .cells()[&vault]
                .clone()
        };
        assert_eq!(first_then_second, second_then_first);
        assert_eq!(read_amount(&first_then_second.unwrap()), Some(300));
    }

    /// A resolved movement is an absolute like any other, and a drained
    /// cell goes rather than encoding zero.
    #[test]
    fn resolving_a_drain_removes_the_cell() {
        let vault = key(2, 2);
        let mut writes = StateWrites::default();
        writes.movements.insert(
            vault,
            Movement {
                credit: 0,
                debit: 500,
            },
        );
        let resolved = writes.resolve(&mut |_| amount_cell(500).map(|cell| cell.to_vec()));
        assert_eq!(resolved.cells()[&vault], None, "a drained cell is absent");
    }

    /// An exclusive write in the same receipt is what the movement folds
    /// onto: the receipt's own absolute stands in for the prior value.
    #[test]
    fn a_movement_folds_onto_this_receipts_own_write() {
        let vault = key(3, 3);
        let mut writes = StateWrites::default();
        writes
            .cells
            .insert(vault, amount_cell(100).map(|cell| cell.to_vec()));
        writes.movements.insert(
            vault,
            Movement {
                credit: 50,
                debit: 0,
            },
        );
        let resolved = writes.resolve(&mut |_| panic!("the receipt's own write is the prior"));
        assert_eq!(
            read_amount(&resolved.cells[&vault].clone().unwrap()),
            Some(150)
        );
    }

    #[test]
    fn unsorted_keys_reject_at_decode() {
        let mut writes = StateWrites::default();
        writes.cells.insert(key(1, 1), Some(vec![7]));
        writes.cells.insert(key(2, 1), Some(vec![8]));
        let sorted = to_vec(&writes).unwrap();
        // The cells map first — one length byte, then two equal-width
        // entries, which is the pair to swap — and the empty movements
        // map contributing its own length byte at the end.
        let mut swapped = sorted.clone();
        let entry_len = 32 + 3; // key, Some tag, value length, one payload byte
        assert_eq!(sorted.len(), 1 + 2 * entry_len + 1);
        for offset in 0..entry_len {
            swapped.swap(1 + offset, 1 + entry_len + offset);
        }
        assert_eq!(
            from_slice::<StateWrites>(&swapped),
            Err(DecodeError::UnsortedKeys)
        );
    }
}
