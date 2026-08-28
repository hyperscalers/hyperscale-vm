//! What one transaction says about state.
//!
//! Two ways of saying it, because two kinds of access earn two kinds of
//! answer. An exclusive write — a cell's value, an ordered-collection
//! entry — knows the value it leaves and reports it absolutely. A
//! commutative access — a delta, a settled reservation — knows only what
//! it moved, and reporting *that* is what keeps the answer true no
//! matter what else touched the cell: an absolute computed against one
//! baseline is wrong the moment a sibling the baseline excluded also
//! lands, while a movement composes with it.
//!
//! An embedder commits absolutes, so movements are folded down by
//! [`StateWrites::resolve`] against whatever the cell holds when the
//! change actually applies. Doing that early — at execution, against the
//! baseline the transaction happened to read — is what throws the
//! property away. `None` is a removal: a drained amount cell resolves to
//! an absent cell, never to an encoded zero.

use std::collections::BTreeMap;

use hyperscale_hbor::{Hash32, Hasher, Hbor, to_vec};

use crate::address::{Address, CollectionId, LocalKey, ResourceAddr, SubstateKey};
use crate::amount::{amount_cell, read_amount};

/// The bytes one committed cell value may carry — one bound for a cell
/// wherever it travels, in a receipt or a provision. A wire bound; the
/// bytes themselves are the storage bond's to price.
pub const MAX_CELL_VALUE_LEN: usize = 2 * 1024 * 1024;

const DOMAIN_ENTRY: &[u8] = b"hyperscale-vm/entry-leaf";

/// One ordered-collection entry's identity: the collection's owner, the
/// collection, and the entry's position in its order space.
///
/// The derived `Ord` — owner, then collection, then order — is the
/// canonical key order the writes maps encode in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct EntryKey {
    /// The collection's owner; fixes the entry's shard.
    pub owner: Address,
    /// The collection under the owner.
    pub collection: CollectionId,
    /// The entry's order key within the collection.
    pub order: u128,
}

/// The leaf key an entry commits under in the state tree: the owner's
/// prefix followed by a digest of the owner, collection, and order.
///
/// Owner-prefixed like every leaf, so reshape's prefix-rooted model
/// moves entries with their owner untouched. Domain-separated from every
/// other local-half derivation, so an entry leaf never aliases a point
/// cell. The owner is salted into the digest for the same reason
/// `child_key` salts it: a collection id can originate outside this
/// derivation, so without the salt one ground collision on the 16-byte
/// local half would reproduce under every owner at once.
#[must_use]
pub fn entry_leaf_key(hasher: &dyn Hasher, entry: EntryKey) -> SubstateKey {
    let owner_bytes = entry.owner.to_bytes();
    let collection_bytes = entry.collection.0;
    let order_bytes = entry.order.to_le_bytes();
    let digest = hasher.hash(
        DOMAIN_ENTRY,
        &[&owner_bytes, &collection_bytes, &order_bytes],
    );
    let mut local = [0u8; 16];
    local.copy_from_slice(&digest.0[..16]);
    SubstateKey {
        owner: entry.owner,
        local: LocalKey(local),
    }
}

/// The self-describing value an entry's leaf carries.
///
/// The collection and order sit beside the entry value, so the ordered
/// index is derivable from the leaves alone — a snap-sync import rebuilds
/// it without any side channel, and two replicas with equal roots hold
/// equal collections.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct EntryLeaf {
    /// The collection under the leaf's owner prefix.
    pub collection: CollectionId,
    /// The entry's order key within the collection.
    pub order: u128,
    /// The entry value.
    pub value: Vec<u8>,
}

/// One transaction's owned state change, keyed canonically.
///
/// Every map decodes only in strictly ascending key order, so every
/// encoding is canonical by construction and equal writes hash equal on
/// every replica.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
#[hbor(validate = cell_values_fit)]
pub struct StateWrites {
    /// The committed value per written byte cell, or `None` for a
    /// removal.
    pub cells: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    /// What this transaction moved on each amount cell it reached,
    /// relative to whatever the cell holds when the movement applies.
    ///
    /// A cell never appears in both maps, and what a cell holds is what
    /// decides which — not how a capability reached it. An exclusive
    /// claim on a value cell governs when the transaction may run and
    /// leaves the record a movement, because the value the cell ends at
    /// is the settling shard's answer and not this transaction's; only a
    /// byte cell has a value to state outright.
    pub movements: BTreeMap<SubstateKey, Movement>,
    /// The committed value per exclusively written ordered-collection
    /// entry, or `None` for a removal.
    ///
    /// Entries are exclusive writes like `cells` — the kernel grants only
    /// range read/write capabilities over collections — so they carry no
    /// movement form and nothing here resolves.
    pub entries: BTreeMap<EntryKey, Option<Vec<u8>>>,
}

/// A change to one amount cell: checked credit and debit totals,
/// relative to whatever the cell holds, in the resource the cell is
/// denominated in.
///
/// Recording the movement rather than the value it would produce is what
/// makes a receipt schedule-invariant — another transaction's compatible
/// movement on the same cell cannot leak into this one, and neither
/// overwrites the other when both settle.
///
/// The resource rides on the movement rather than being looked up from
/// the declaration that authorised it, which is what lets a receipt
/// answer what it moved without anything beside it, and lets a movement
/// exist at all where no package declared the cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub struct Movement {
    /// What the moved cell holds.
    pub resource: ResourceAddr,
    /// Total credited.
    pub credit: u128,
    /// Total debited.
    pub debit: u128,
}

impl Movement {
    /// Nothing moved, in `resource`.
    ///
    /// There is no `Default`: a movement names what it moves, and a
    /// resource nobody chose would be a denomination invented here.
    #[must_use]
    pub const fn none(resource: ResourceAddr) -> Self {
        Self {
            resource,
            credit: 0,
            debit: 0,
        }
    }

    /// A debit of `amount`, which is what a settled reservation is.
    #[must_use]
    pub const fn debit(resource: ResourceAddr, amount: u128) -> Self {
        Self {
            resource,
            credit: 0,
            debit: amount,
        }
    }

    /// This movement followed by `next` on the same cell, or `None`
    /// where a composed total leaves `u128`.
    ///
    /// Checked rather than saturating: the totals a kernel records are
    /// bounded by the balances that fed them, so a sum past `u128` is a
    /// movement no kernel produced — a malformed receipt for the caller
    /// to refuse whole, not a total to pin at the ceiling and settle on.
    ///
    /// # Panics
    ///
    /// Debug-only, if the two name different resources: one cell holds
    /// one resource, so composing across two is the kernel disagreeing
    /// with itself rather than anything a caller can cause.
    #[must_use]
    pub fn then(self, next: Self) -> Option<Self> {
        debug_assert_eq!(
            self.resource, next.resource,
            "composing movements of different resources on one cell",
        );
        Some(Self {
            resource: self.resource,
            credit: self.credit.checked_add(next.credit)?,
            debit: self.debit.checked_add(next.debit)?,
        })
    }

    /// `before` with this movement applied, or `None` if the debit runs
    /// past what the cell holds.
    ///
    /// The two sides net before they touch `before`, so a movement whose
    /// credit and debit both land on one cell cannot overflow on a net that
    /// fits: only a genuine debit past the balance returns `None`. This
    /// matches the execution-side fold in `fold_deltas`, which the settled
    /// value must agree with.
    #[must_use]
    pub const fn apply(self, before: u128) -> Option<u128> {
        if self.credit >= self.debit {
            before.checked_add(self.credit - self.debit)
        } else {
            before.checked_sub(self.debit - self.credit)
        }
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
        SettledWrites {
            cells,
            entries: self.entries.clone(),
        }
    }

    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.movements.is_empty() && self.entries.is_empty()
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
    entries: BTreeMap<EntryKey, Option<Vec<u8>>>,
}

impl SettledWrites {
    /// Cell writes that are already values — genesis, a provision, a
    /// store's own snapshot. Nothing here moved, so nothing needs
    /// resolving; entries are empty.
    #[must_use]
    pub const fn from_absolutes(cells: SettledCells) -> Self {
        Self {
            cells,
            entries: BTreeMap::new(),
        }
    }

    /// Both maps at once — the inverse of [`Self::into_parts`], for a
    /// consumer that filtered or rebuilt a settled set and owns the
    /// result. Entries were absolute all along, so nothing needs
    /// resolving on either side.
    #[must_use]
    pub const fn from_parts(cells: SettledCells, entries: SettledEntries) -> Self {
        Self { cells, entries }
    }

    /// The committed value per changed cell, or `None` for a removal.
    #[must_use]
    pub const fn cells(&self) -> &BTreeMap<SubstateKey, Option<Vec<u8>>> {
        &self.cells
    }

    /// The committed value per changed ordered-collection entry, or
    /// `None` for a removal. Entries never move, so they were absolute
    /// all along.
    #[must_use]
    pub const fn entries(&self) -> &BTreeMap<EntryKey, Option<Vec<u8>>> {
        &self.entries
    }

    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.entries.is_empty()
    }

    /// Take both maps, for a consumer that owns them from here. A pair
    /// rather than a cells accessor, so taking the values cannot silently
    /// leave the entries behind.
    #[must_use]
    pub fn into_parts(self) -> (SettledCells, SettledEntries) {
        (self.cells, self.entries)
    }
}

/// The committed value per changed cell, `None` a removal.
pub type SettledCells = BTreeMap<SubstateKey, Option<Vec<u8>>>;

/// The committed value per changed ordered-collection entry, `None` a
/// removal.
pub type SettledEntries = BTreeMap<EntryKey, Option<Vec<u8>>>;

impl From<SettledWrites> for StateWrites {
    /// Values are a receipt payload like any other — they are the half
    /// of one that never moved. The reverse needs a prior and so is
    /// [`StateWrites::resolve`], not a conversion.
    fn from(settled: SettledWrites) -> Self {
        let (cells, entries) = settled.into_parts();
        Self {
            cells,
            movements: BTreeMap::new(),
            entries,
        }
    }
}

fn cell_values_fit(writes: &StateWrites) -> Result<(), &'static str> {
    if writes
        .cells
        .values()
        .chain(writes.entries.values())
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
    use hyperscale_hbor::hash::TestHasher;
    use hyperscale_hbor::{DecodeError, assert_canonical, from_slice, to_vec};

    use super::{
        EntryKey, EntryLeaf, MAX_CELL_VALUE_LEN, Movement, ResourceAddr, StateWrites,
        entry_leaf_key,
    };
    use crate::address::{
        Address, AddressClass, CollectionId, LEAF_KEY_BYTES, LocalKey, SubstateKey,
    };

    /// What every cell these fixtures move holds.
    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
    use crate::amount::{amount_cell, read_amount};

    fn key(owner: u8, local: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            local: LocalKey([local; 16]),
        }
    }

    fn entry(owner: u8, collection: u8, order: u128) -> EntryKey {
        EntryKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            collection: CollectionId([collection; 16]),
            order,
        }
    }

    #[test]
    fn writes_are_canonical() {
        let mut writes = StateWrites::default();
        writes.cells.insert(key(1, 1), Some(vec![7]));
        writes.cells.insert(key(1, 2), None);
        writes.cells.insert(key(2, 1), Some(vec![]));
        writes.entries.insert(entry(1, 4, 7), Some(vec![9]));
        writes.entries.insert(entry(1, 4, 8), None);
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

    #[test]
    fn an_oversized_entry_value_rejects_at_decode() {
        // The cell cap bounds entry values too — an entry travels in the
        // same receipts and provisions a cell does.
        let mut writes = StateWrites::default();
        writes
            .entries
            .insert(entry(1, 4, 7), Some(vec![0; MAX_CELL_VALUE_LEN + 1]));
        let bytes = to_vec(&writes).unwrap();
        assert!(matches!(
            from_slice::<StateWrites>(&bytes),
            Err(DecodeError::FailedValidation(_))
        ));
    }

    /// The root covers entries: two writes maps differing only in an
    /// entry hash differently, and an entries-only map is not empty.
    #[test]
    fn the_root_moves_when_entries_do() {
        let hash_fn = |bytes: &[u8]| {
            let mut out = [0u8; 32];
            let digest = bytes.iter().fold(11u64, |acc, byte| {
                acc.wrapping_mul(31).wrapping_add(u64::from(*byte))
            });
            out[..8].copy_from_slice(&digest.to_le_bytes());
            out
        };
        let empty = StateWrites::default();
        let mut written = StateWrites::default();
        written.entries.insert(entry(1, 4, 7), Some(vec![9]));
        assert_ne!(empty.root(hash_fn), written.root(hash_fn));
        let mut removed = StateWrites::default();
        removed.entries.insert(entry(1, 4, 7), None);
        assert_ne!(written.root(hash_fn), removed.root(hash_fn));
        assert!(!written.is_empty());
    }

    /// Entries pass through resolution untouched: they are exclusive
    /// writes, so nothing about them depends on a prior value.
    #[test]
    fn entries_resolve_through_untouched() {
        let mut writes = StateWrites::default();
        writes.entries.insert(entry(1, 4, 7), Some(vec![9]));
        writes.entries.insert(entry(1, 4, 8), None);
        let settled = writes.resolve(&mut |_| panic!("no cell is read"));
        assert_eq!(settled.entries(), &writes.entries);
        assert!(!settled.is_empty());

        let round_tripped = StateWrites::from(settled);
        assert_eq!(round_tripped.entries, writes.entries);
    }

    /// An entry's leaf sits under its owner's prefix, distinct entries
    /// take distinct leaves, and the leaf value describes itself.
    #[test]
    fn entry_leaves_stay_under_the_owner() {
        let first = entry_leaf_key(&TestHasher, entry(1, 4, 7));
        assert_eq!(first.owner, Address::new([1; 31], AddressClass::Component));
        // The owner varies the local half too: the salt that keeps a
        // ground collision from reproducing under every owner at once.
        for other in [entry(1, 4, 8), entry(1, 5, 7), entry(2, 4, 7)] {
            assert_ne!(first.local, entry_leaf_key(&TestHasher, other).local);
        }
        assert_canonical(&EntryLeaf {
            collection: CollectionId([4; 16]),
            order: 7,
            value: vec![9],
        });
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
                    resource: RESOURCE,
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
                resource: RESOURCE,
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
                resource: RESOURCE,
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

    /// A net-zero pass-through onto a near-max cell nets to the balance it
    /// found, not to zero: crediting before debiting would overflow on a net
    /// that fits and drop the leaf. This is the case the execution-side
    /// `fold_deltas` reports as `CellOverflow`; settlement, which cannot
    /// error, must land the correct net instead.
    #[test]
    fn a_net_fitting_movement_does_not_overflow_to_zero() {
        let near_max = u128::MAX - 50;
        let pass_through = Movement {
            resource: RESOURCE,
            credit: 100,
            debit: 100,
        };
        assert_eq!(pass_through.apply(near_max), Some(near_max));

        // A genuine debit past the balance still saturates at the caller.
        let overdraw = Movement {
            resource: RESOURCE,
            credit: 10,
            debit: 20,
        };
        assert_eq!(overdraw.apply(5), None);

        let vault = key(4, 4);
        let mut writes = StateWrites::default();
        writes.movements.insert(vault, pass_through);
        let resolved = writes.resolve(&mut |_| amount_cell(near_max).map(|cell| cell.to_vec()));
        assert_eq!(
            read_amount(&resolved.cells[&vault].clone().unwrap()),
            Some(near_max)
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
        // and entries maps each contributing a length byte at the end.
        let mut swapped = sorted.clone();
        // key, Some tag, value length, one payload byte
        let entry_len = LEAF_KEY_BYTES + 3;
        assert_eq!(sorted.len(), 1 + 2 * entry_len + 2);
        for offset in 0..entry_len {
            swapped.swap(1 + offset, 1 + entry_len + offset);
        }
        assert_eq!(
            from_slice::<StateWrites>(&swapped),
            Err(DecodeError::UnsortedKeys)
        );
    }
}
