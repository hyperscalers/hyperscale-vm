//! The flattened form of one transaction's state change.
//!
//! A receipt's delta records movements and settlements relative to
//! committed state; [`StateWrites`] is that delta folded down to the
//! absolute cell outcomes an embedder commits, and the value the writes
//! attestation hashes. `None` is a removal: a drained amount cell
//! flattens to an absent cell, never to an encoded zero.

use std::collections::BTreeMap;

use hyperscale_hbor::{Hash32, Hbor, to_vec};

use crate::address::SubstateKey;

/// The bytes one committed cell value may carry — one bound for a cell
/// wherever it travels, in a receipt or a provision.
pub const MAX_CELL_VALUE_LEN: usize = 2 * 1024 * 1024;

/// Absolute cell outcomes keyed canonically; `None` removes the cell.
///
/// The map decodes only in strictly ascending key order, so every
/// encoding is canonical by construction and equal writes hash equal on
/// every replica.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
#[hbor(validate = cell_values_fit)]
pub struct StateWrites {
    /// The committed value per changed cell, or `None` for a removal.
    pub cells: BTreeMap<SubstateKey, Option<Vec<u8>>>,
}

impl StateWrites {
    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// The canonical commitment to these writes: `hash_fn` over the
    /// canonical encoding.
    #[must_use]
    pub fn root(&self, hash_fn: fn(&[u8]) -> [u8; 32]) -> Hash32 {
        Hash32(hash_fn(
            &to_vec(self).expect("state writes stay within the encoder's bounds"),
        ))
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

    use super::{MAX_CELL_VALUE_LEN, StateWrites};
    use crate::address::{Address, LocalKey, SubstateKey};

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

    #[test]
    fn unsorted_keys_reject_at_decode() {
        let mut writes = StateWrites::default();
        writes.cells.insert(key(1, 1), Some(vec![7]));
        writes.cells.insert(key(2, 1), Some(vec![8]));
        let sorted = to_vec(&writes).unwrap();
        // One length byte, then two equal-width entries: swap them.
        let mut swapped = sorted.clone();
        let entry_len = 32 + 3; // key, Some tag, value length, one payload byte
        assert_eq!(sorted.len(), 1 + 2 * entry_len);
        for offset in 0..entry_len {
            swapped.swap(1 + offset, 1 + entry_len + offset);
        }
        assert_eq!(
            from_slice::<StateWrites>(&swapped),
            Err(DecodeError::UnsortedKeys)
        );
    }
}
